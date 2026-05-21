import { HTMLFormatter } from '../../../src/formatters/html-formatter';
import { FormatterType } from '../../../src/formatters/formatter-interface';
import { ScanResult, ScannerType, ThreatCategory } from '../../../src/core/scanner-interface';
import { Severity } from '../../../src/core/severity';

describe('HTMLFormatter', () => {
  let formatter: HTMLFormatter;

  beforeEach(() => {
    formatter = new HTMLFormatter();
  });

  describe('constructor', () => {
    it('should create a formatter with correct name', () => {
      expect(formatter.name).toBe('HTML Formatter');
    });
  });

  describe('getType', () => {
    it('should return FormatterType.HTML', () => {
      expect(formatter.getType()).toBe(FormatterType.HTML);
    });
  });

  describe('format', () => {
    it('should return input string unchanged', () => {
      const input = 'test string';
      expect(formatter.format(input)).toBe(input);
    });

    it('should handle empty string', () => {
      expect(formatter.format('')).toBe('');
    });
  });

  describe('escapeHtml', () => {
    it('should escape ampersands', () => {
      const results: ScanResult[] = [
        {
          id: 'test',
          filePath: '/test.ts',
          lineNumber: 1,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Test',
          evidence: 'a & b',
          scannerType: ScannerType.Pattern,
        },
      ];

      const summary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 1,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(results, summary);
      expect(output).toContain('a &amp; b');
      expect(output).not.toContain('a & b');
    });

    it('should escape less than signs', () => {
      const results: ScanResult[] = [
        {
          id: 'test',
          filePath: '/test.ts',
          lineNumber: 1,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Test',
          evidence: 'if (a < b)',
          scannerType: ScannerType.Pattern,
        },
      ];

      const summary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 1,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(results, summary);
      expect(output).toContain('if (a &lt; b)');
      expect(output).not.toContain('if (a < b)');
    });

    it('should escape greater than signs', () => {
      const results: ScanResult[] = [
        {
          id: 'test',
          filePath: '/test.ts',
          lineNumber: 1,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Test',
          evidence: 'if (a > b)',
          scannerType: ScannerType.Pattern,
        },
      ];

      const summary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 1,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(results, summary);
      expect(output).toContain('if (a &gt; b)');
      expect(output).not.toContain('if (a > b)');
    });

    it('should escape double quotes', () => {
      const results: ScanResult[] = [
        {
          id: 'test',
          filePath: '/test.ts',
          lineNumber: 1,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Test',
          evidence: 'const x = "value"',
          scannerType: ScannerType.Pattern,
        },
      ];

      const summary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 1,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(results, summary);
      expect(output).toContain('const x = &quot;value&quot;');
      expect(output).not.toContain('const x = "value"');
    });

    it('should escape single quotes', () => {
      const results: ScanResult[] = [
        {
          id: 'test',
          filePath: '/test.ts',
          lineNumber: 1,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Test',
          evidence: "it's a test",
          scannerType: ScannerType.Pattern,
        },
      ];

      const summary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 1,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(results, summary);
      expect(output).toContain('it&#039;s a test');
      expect(output).not.toContain("it's a test");
    });
  });

  describe('formatResults', () => {
    const mockResults: ScanResult[] = [
      {
        id: 'result-1',
        filePath: '/path/to/file1.ts',
        lineNumber: 10,
        severity: Severity.Critical,
        category: ThreatCategory.PromptInjection,
        description: 'Critical security issue found',
        evidence: 'eval(userInput)',
        suggestion: 'Use safe alternatives to eval',
        scannerType: ScannerType.Pattern,
      },
      {
        id: 'result-2',
        filePath: '/path/to/file2.ts',
        lineNumber: 25,
        severity: Severity.High,
        category: ThreatCategory.HardcodedSecret,
        description: 'Hardcoded API key detected',
        evidence: 'api_key = "sk-1234567890"',
        suggestion: 'Use environment variables',
        scannerType: ScannerType.AST,
      },
    ];

    const mockSummary = {
      totalFilesScanned: 42,
      totalIssuesFound: 2,
      issuesBySeverity: {
        [Severity.Info]: 0,
        [Severity.Low]: 0,
        [Severity.Medium]: 0,
        [Severity.High]: 1,
        [Severity.Critical]: 1,
      },
      issuesByCategory: {
        [ThreatCategory.PromptInjection]: 1,
        [ThreatCategory.HardcodedSecret]: 1,
      },
      scanDurationMs: 1500,
    };

    it('should include HTML doctype declaration', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('<!DOCTYPE html>');
    });

    it('should include html and body tags', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('<html>');
      expect(output).toContain('<head>');
      expect(output).toContain('<body>');
    });

    it('should include title tag', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('<title>AIAgentAntivirus Scan Report</title>');
    });

    it('should include styles', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('<style>');
      expect(output).toContain('font-family: system-ui');
    });

    it('should include report header', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('AIAgentAntivirus Scan Report');
      expect(output).toContain('Generated:');
    });

    it('should include summary section', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('Summary');
      expect(output).toContain('Files scanned:');
      expect(output).toContain('42');
      expect(output).toContain('Total issues:');
      expect(output).toContain('2');
      expect(output).toContain('Duration:');
    });

    it('should include severity breakdown in summary', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('high: 1');
      expect(output).toContain('critical: 1');
    });

    it('should format duration correctly', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('1.50s');
    });

    it('should include result cards', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('class="result"');
    });

    it('should include file location in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('/path/to/file1.ts:10');
      expect(output).toContain('/path/to/file2.ts:25');
    });

    it('should include severity in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('CRITICAL');
      expect(output).toContain('HIGH');
    });

    it('should include category in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain(ThreatCategory.PromptInjection);
      expect(output).toContain(ThreatCategory.HardcodedSecret);
    });

    it('should include description in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('Critical security issue found');
      expect(output).toContain('Hardcoded API key detected');
    });

    it('should include evidence in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('eval(userInput)');
      expect(output).toContain('api_key = &quot;sk-1234567890&quot;');
    });

    it('should include suggestion in results', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('Use safe alternatives to eval');
      expect(output).toContain('Use environment variables');
    });

    it('should apply correct severity colors', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('#ef4444'); // Critical color
      expect(output).toContain('#f97316'); // High color
    });

    it('should handle empty results array', () => {
      const emptyResults: ScanResult[] = [];
      const emptySummary = {
        totalFilesScanned: 10,
        totalIssuesFound: 0,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 0,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: {},
        scanDurationMs: 500,
      };

      const output = formatter.formatResults(emptyResults, emptySummary);
      expect(output).toContain('No security issues found!');
      expect(output).not.toContain('class="result"');
    });

    it('should handle results without optional fields', () => {
      const minimalResults: ScanResult[] = [
        {
          id: 'minimal-1',
          filePath: '/path/to/file.ts',
          lineNumber: 5,
          severity: Severity.Info,
          category: ThreatCategory.Other,
          description: 'Info message',
          scannerType: ScannerType.Pattern,
        },
      ];

      const minimalSummary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 1,
          [Severity.Low]: 0,
          [Severity.Medium]: 0,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(minimalResults, minimalSummary);
      expect(output).toContain('Info message');
      expect(output).toContain('INFO');
      expect(output).toContain('#3b82f6'); // Info color
    });

    it('should handle all severity levels', () => {
      const allSeverityResults: ScanResult[] = [
        { ...mockResults[0], id: 'info', severity: Severity.Info },
        { ...mockResults[0], id: 'low', severity: Severity.Low },
        { ...mockResults[0], id: 'medium', severity: Severity.Medium },
        { ...mockResults[0], id: 'high', severity: Severity.High },
        { ...mockResults[0], id: 'critical', severity: Severity.Critical },
      ];

      const allSeveritySummary = {
        totalFilesScanned: 5,
        totalIssuesFound: 5,
        issuesBySeverity: {
          [Severity.Info]: 1,
          [Severity.Low]: 1,
          [Severity.Medium]: 1,
          [Severity.High]: 1,
          [Severity.Critical]: 1,
        },
        issuesByCategory: { [ThreatCategory.PromptInjection]: 5 },
        scanDurationMs: 1000,
      };

      const output = formatter.formatResults(allSeverityResults, allSeveritySummary);
      expect(output).toContain('INFO');
      expect(output).toContain('LOW');
      expect(output).toContain('MEDIUM');
      expect(output).toContain('HIGH');
      expect(output).toContain('CRITICAL');
      expect(output).toContain('#3b82f6'); // Info
      expect(output).toContain('#06b6d4'); // Low
      expect(output).toContain('#eab308'); // Medium
      expect(output).toContain('#f97316'); // High
      expect(output).toContain('#ef4444'); // Critical
    });

    it('should not include zero-count severities in summary', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).not.toContain('info: 0');
      expect(output).not.toContain('low: 0');
      expect(output).not.toContain('medium: 0');
    });

    it('should handle special characters in file paths', () => {
      const specialResults: ScanResult[] = [
        {
          id: 'special',
          filePath: '/path/to/file with spaces & "quotes".ts',
          lineNumber: 1,
          severity: Severity.Medium,
          category: ThreatCategory.Other,
          description: 'Test with special characters',
          evidence: '<script>alert("XSS")</script>',
          scannerType: ScannerType.Pattern,
        },
      ];

      const specialSummary = {
        totalFilesScanned: 1,
        totalIssuesFound: 1,
        issuesBySeverity: {
          [Severity.Info]: 0,
          [Severity.Low]: 0,
          [Severity.Medium]: 1,
          [Severity.High]: 0,
          [Severity.Critical]: 0,
        },
        issuesByCategory: { [ThreatCategory.Other]: 1 },
        scanDurationMs: 100,
      };

      const output = formatter.formatResults(specialResults, specialSummary);
      // HTML should be escaped in evidence
      expect(output).toContain('&lt;script&gt;');
      expect(output).not.toContain('<script>');
    });
  });
});
