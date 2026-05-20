import { ResultAggregator } from '../../../src/core/result';
import { ScanResult, ScannerType, ThreatCategory } from '../../../src/core/scanner-interface';
import { Severity } from '../../../src/core/severity';

describe('ResultAggregator', () => {
  let aggregator: ResultAggregator;
  const mockResult: ScanResult = {
    id: 'test-1',
    filePath: '/test/file.js',
    lineNumber: 10,
    severity: Severity.High,
    category: ThreatCategory.PromptInjection,
    description: 'Test issue',
    scannerType: ScannerType.Pattern
  };

  beforeEach(() => {
    aggregator = new ResultAggregator();
  });

  describe('add', () => {
    it('should add a single result', () => {
      aggregator.add(mockResult);
      expect(aggregator.getResults()).toHaveLength(1);
      expect(aggregator.getResults()[0]).toEqual(mockResult);
    });
  });

  describe('addAll', () => {
    it('should add multiple results', () => {
      aggregator.addAll([mockResult, { ...mockResult, id: 'test-2' }]);
      expect(aggregator.getResults()).toHaveLength(2);
    });
  });

  describe('getSummary', () => {
    it('should generate correct summary', () => {
      aggregator.add(mockResult);
      const summary = aggregator.getSummary(5, 1000);

      expect(summary.totalFilesScanned).toBe(5);
      expect(summary.totalIssuesFound).toBe(1);
      expect(summary.issuesBySeverity.high).toBe(1);
      expect(summary.scanDurationMs).toBe(1000);
    });
  });

  describe('getExitCode', () => {
    it('should return 0 for no issues', () => {
      expect(aggregator.getExitCode()).toBe(0);
    });

    it('should return 1 for non-critical issues', () => {
      aggregator.add({ ...mockResult, severity: Severity.Low });
      expect(aggregator.getExitCode()).toBe(1);
    });

    it('should return 2 for critical issues', () => {
      aggregator.add({ ...mockResult, severity: Severity.Critical });
      expect(aggregator.getExitCode()).toBe(2);
    });
  });
});