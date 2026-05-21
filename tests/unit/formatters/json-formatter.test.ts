import { JSONFormatter } from '../../../src/formatters/json-formatter';
import { FormatterType } from '../../../src/formatters/formatter-interface';
import { ScanResult, ScannerType, ThreatCategory } from '../../../src/core/scanner-interface';
import { Severity } from '../../../src/core/severity';

describe('JSONFormatter', () => {
  let formatter: JSONFormatter;

  beforeEach(() => {
    formatter = new JSONFormatter();
  });

  describe('constructor', () => {
    it('should create a formatter with correct name', () => {
      expect(formatter.name).toBe('JSON Formatter');
    });
  });

  describe('getType', () => {
    it('should return FormatterType.JSON', () => {
      expect(formatter.getType()).toBe(FormatterType.JSON);
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

    it('should format results as valid JSON', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should include version field', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.version).toBe('0.0.1');
    });

    it('should include timestamp field', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.timestamp).toBeDefined();
      expect(new Date(parsed.timestamp)).toBeInstanceOf(Date);
    });

    it('should include summary with all fields', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.summary).toBeDefined();
      expect(parsed.summary.totalFilesScanned).toBe(42);
      expect(parsed.summary.totalIssuesFound).toBe(2);
      expect(parsed.summary.scanDurationMs).toBe(1500);
    });

    it('should include issuesBySeverity in summary', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.summary.issuesBySeverity).toEqual({
        [Severity.Info]: 0,
        [Severity.Low]: 0,
        [Severity.Medium]: 0,
        [Severity.High]: 1,
        [Severity.Critical]: 1,
      });
    });

    it('should include issuesByCategory in summary', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.summary.issuesByCategory).toEqual({
        [ThreatCategory.PromptInjection]: 1,
        [ThreatCategory.HardcodedSecret]: 1,
      });
    });

    it('should include all results with all fields', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.results).toHaveLength(2);

      const firstResult = parsed.results[0];
      expect(firstResult.id).toBe('result-1');
      expect(firstResult.filePath).toBe('/path/to/file1.ts');
      expect(firstResult.lineNumber).toBe(10);
      expect(firstResult.severity).toBe(Severity.Critical);
      expect(firstResult.category).toBe(ThreatCategory.PromptInjection);
      expect(firstResult.description).toBe('Critical security issue found');
      expect(firstResult.evidence).toBe('eval(userInput)');
      expect(firstResult.suggestion).toBe('Use safe alternatives to eval');
      expect(firstResult.scannerType).toBe(ScannerType.Pattern);
    });

    it('should handle results with optional fields missing', () => {
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
      const parsed = JSON.parse(output);
      expect(parsed.results[0].evidence).toBeUndefined();
      expect(parsed.results[0].suggestion).toBeUndefined();
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
      const parsed = JSON.parse(output);
      expect(parsed.results).toEqual([]);
      expect(parsed.summary.totalIssuesFound).toBe(0);
    });

    it('should format JSON with 2-space indentation', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('  "version"');
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
      const parsed = JSON.parse(output);
      expect(parsed.results).toHaveLength(5);
      expect(parsed.results.map((r: any) => r.severity)).toEqual([
        Severity.Info,
        Severity.Low,
        Severity.Medium,
        Severity.High,
        Severity.Critical,
      ]);
    });

    it('should escape special characters in strings', () => {
      const specialResults: ScanResult[] = [
        {
          id: 'special',
          filePath: '/path/to/file with "quotes".ts',
          lineNumber: 1,
          severity: Severity.Medium,
          category: ThreatCategory.Other,
          description: 'Issue with "quotes" and \n newlines',
          evidence: 'Code with "special" chars',
          suggestion: 'Fix "this"',
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
      expect(() => JSON.parse(output)).not.toThrow();
      const parsed = JSON.parse(output);
      expect(parsed.results[0].filePath).toContain('quotes');
    });
  });
});
