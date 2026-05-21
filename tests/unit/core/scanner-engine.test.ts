import { ScannerEngine } from '../../../src/core/scanner-engine';
import { Scanner, ScannerType } from '../../../src/core/scanner-interface';
import { Severity } from '../../../src/core/severity';
import { ThreatCategory } from '../../../src/core/scanner-interface';

class MockScanner implements Scanner {
  readonly name = 'Mock Scanner';
  readonly type: ScannerType;

  constructor(type: ScannerType) {
    this.type = type;
  }

  async scan(_filePath: string, _content: string): Promise<any[]> {
    return [{
      id: `mock-${Date.now()}`,
      filePath: _filePath,
      lineNumber: 1,
      severity: Severity.Low,
      category: ThreatCategory.Other,
      description: 'Mock result',
      scannerType: this.type
    }];
  }
}

describe('ScannerEngine', () => {
  let engine: ScannerEngine;

  beforeEach(() => {
    engine = new ScannerEngine();
  });

  describe('registerScanner', () => {
    it('should register scanners', () => {
      const scanner = new MockScanner(ScannerType.Pattern);
      engine.registerScanner(scanner);

      expect(engine.getScannerCount()).toBe(1);
    });
  });

  describe('scanFiles', () => {
    it('should scan files with registered scanners', async () => {
      const scanner = new MockScanner(ScannerType.Pattern);
      engine.registerScanner(scanner);

      const files = [
        { path: '/test/file.js', content: 'test content' }
      ];

      const result = await engine.scanFiles(files);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].scannerType).toBe(ScannerType.Pattern);
    });

    it('should handle multiple scanners', async () => {
      const patternScanner = new MockScanner(ScannerType.Pattern);
      const astScanner = new MockScanner(ScannerType.AST);
      engine.registerScanner(patternScanner);
      engine.registerScanner(astScanner);

      const files = [{ path: '/test/file.js', content: 'test' }];

      const result = await engine.scanFiles(files);

      expect(result.results).toHaveLength(2);
    });

    it('should filter by enabled scanners', async () => {
      const patternScanner = new MockScanner(ScannerType.Pattern);
      const astScanner = new MockScanner(ScannerType.AST);
      engine.registerScanner(patternScanner);
      engine.registerScanner(astScanner);

      const files = [{ path: '/test/file.js', content: 'test' }];

      const result = await engine.scanFiles(files, {
        enabledScanners: [ScannerType.Pattern]
      });

      expect(result.results).toHaveLength(1);
      expect(result.results[0].scannerType).toBe(ScannerType.Pattern);
    });
  });

  describe('parallelism', () => {
    it('should process files in parallel when parallelism > 1', async () => {
      const scanner = new MockScanner(ScannerType.Pattern);
      engine = new ScannerEngine({ parallelism: 2 });
      engine.registerScanner(scanner);

      const files = [
        { path: '/test/file1.js', content: 'test1' },
        { path: '/test/file2.js', content: 'test2' }
      ];

      const result = await engine.scanFiles(files);

      expect(result.results).toHaveLength(2);
    });
  });
});