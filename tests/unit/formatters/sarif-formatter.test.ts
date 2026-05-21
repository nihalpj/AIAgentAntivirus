import { SARIFFormatter } from '../../../src/formatters/sarif-formatter';
import { FormatterType } from '../../../src/formatters/formatter-interface';
import { ScanResult, ScannerType, ThreatCategory } from '../../../src/core/scanner-interface';
import { Severity } from '../../../src/core/severity';

describe('SARIFFormatter', () => {
  let formatter: SARIFFormatter;

  beforeEach(() => {
    formatter = new SARIFFormatter();
  });

  describe('constructor', () => {
    it('should create a formatter with correct name', () => {
      expect(formatter.name).toBe('SARIF Formatter');
    });
  });

  describe('getType', () => {
    it('should return FormatterType.SARIF', () => {
      expect(formatter.getType()).toBe(FormatterType.SARIF);
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

    it('should include SARIF version 2.1.0', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.version).toBe('2.1.0');
    });

    it('should include SARIF schema URL', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    });

    it('should include runs array', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs).toBeDefined();
      expect(Array.isArray(parsed.runs)).toBe(true);
      expect(parsed.runs).toHaveLength(1);
    });

    it('should include tool driver information', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].tool.driver.name).toBe('aiav');
      expect(parsed.runs[0].tool.driver.version).toBe('0.0.1');
      expect(parsed.runs[0].tool.driver.informationUri).toBe(
        'https://github.com/anthropics/aiagentantivirus'
      );
    });

    it('should include rules for each result', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].tool.driver.rules).toHaveLength(2);

      const firstRule = parsed.runs[0].tool.driver.rules[0];
      expect(firstRule.id).toBe('result-1');
      expect(firstRule.name).toBe(ThreatCategory.PromptInjection);
      expect(firstRule.shortDescription.text).toBe('Critical security issue found');
      expect(firstRule.fullDescription.text).toBe('Critical security issue found');
      expect(firstRule.help.text).toBe('Use safe alternatives to eval');
    });

    it('should include results array', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].results).toHaveLength(2);
    });

    it('should map severity levels correctly', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      const levels = parsed.runs[0].results.map((r: any) => r.level);
      expect(levels).toContain('error'); // Critical and High should be error
      expect(levels).not.toContain('note');
      expect(levels).not.toContain('warning');
    });

    it('should include ruleId in each result', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].results[0].ruleId).toBe('result-1');
      expect(parsed.runs[0].results[1].ruleId).toBe('result-2');
    });

    it('should include message in each result', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].results[0].message.text).toBe('Critical security issue found');
      expect(parsed.runs[0].results[1].message.text).toBe('Hardcoded API key detected');
    });

    it('should include physicalLocation in each result', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      const loc1 = parsed.runs[0].results[0].locations[0].physicalLocation;
      expect(loc1.artifactLocation.uri).toBe('/path/to/file1.ts');
      expect(loc1.region.startLine).toBe(10);
      expect(loc1.region.endLine).toBe(10);
    });

    it('should include codeFlows when evidence is present', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].results[0].codeFlows).toBeDefined();
      expect(
        parsed.runs[0].results[0].codeFlows[0].threadFlows[0].locations[0].location.message.text
      ).toBe('eval(userInput)');
    });

    it('should not include codeFlows when evidence is absent', () => {
      const noEvidenceResults: ScanResult[] = [
        {
          id: 'no-evidence',
          filePath: '/path/to/file.ts',
          lineNumber: 5,
          severity: Severity.Low,
          category: ThreatCategory.Other,
          description: 'Issue without evidence',
          scannerType: ScannerType.Pattern,
        },
      ];

      const noEvidenceSummary = {
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

      const output = formatter.formatResults(noEvidenceResults, noEvidenceSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].results[0].codeFlows).toBeUndefined();
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
      expect(parsed.runs[0].tool.driver.rules).toEqual([]);
      expect(parsed.runs[0].results).toEqual([]);
    });

    it('should handle results without suggestion', () => {
      const noSuggestionResults: ScanResult[] = [
        {
          id: 'no-suggestion',
          filePath: '/path/to/file.ts',
          lineNumber: 5,
          severity: Severity.Medium,
          category: ThreatCategory.Other,
          description: 'Issue without suggestion',
          scannerType: ScannerType.Pattern,
        },
      ];

      const noSuggestionSummary = {
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

      const output = formatter.formatResults(noSuggestionResults, noSuggestionSummary);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].tool.driver.rules[0].help.text).toBe('No suggestion available');
    });

    it('should map all severity levels correctly', () => {
      const severityTests = [
        { severity: Severity.Info, expectedLevel: 'note' },
        { severity: Severity.Low, expectedLevel: 'warning' },
        { severity: Severity.Medium, expectedLevel: 'warning' },
        { severity: Severity.High, expectedLevel: 'error' },
        { severity: Severity.Critical, expectedLevel: 'error' },
      ];

      severityTests.forEach(({ severity, expectedLevel }) => {
        const results: ScanResult[] = [
          {
            id: `test-${severity}`,
            filePath: '/test.ts',
            lineNumber: 1,
            severity,
            category: ThreatCategory.Other,
            description: 'Test',
            scannerType: ScannerType.Pattern,
          },
        ];

        const summary = {
          totalFilesScanned: 1,
          totalIssuesFound: 1,
          issuesBySeverity: {
            [Severity.Info]: severity === Severity.Info ? 1 : 0,
            [Severity.Low]: severity === Severity.Low ? 1 : 0,
            [Severity.Medium]: severity === Severity.Medium ? 1 : 0,
            [Severity.High]: severity === Severity.High ? 1 : 0,
            [Severity.Critical]: severity === Severity.Critical ? 1 : 0,
          },
          issuesByCategory: { [ThreatCategory.Other]: 1 },
          scanDurationMs: 100,
        };

        const output = formatter.formatResults(results, summary);
        const parsed = JSON.parse(output);
        expect(parsed.runs[0].results[0].level).toBe(expectedLevel);
      });
    });

    it('should format JSON with 2-space indentation', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      expect(output).toContain('  "version"');
    });

    it('should include multiple rules when results have different IDs', () => {
      const output = formatter.formatResults(mockResults, mockSummary);
      const parsed = JSON.parse(output);
      const ruleIds = parsed.runs[0].tool.driver.rules.map((r: any) => r.id);
      expect(ruleIds).toContain('result-1');
      expect(ruleIds).toContain('result-2');
    });
  });
});
