import { ASTScanner } from '../../../src/scanners/ast-scanner';

describe('ASTScanner', () => {
  let scanner: ASTScanner;

  beforeEach(() => {
    scanner = new ASTScanner();
  });

  describe('scan', () => {
    it('should return empty results when parsers unavailable', async () => {
      const content = 'const result = eval("2 + 2");';
      const results = await scanner.scan('/test/file.js', content);
      expect(results).toBeDefined();
    });

    it('should handle parse errors gracefully', async () => {
      const content = 'invalid javascript {{{';
      const results = await scanner.scan('/test/file.js', content);
      expect(results).toHaveLength(0);
    });

    it('should skip unsupported file types', async () => {
      const content = 'some content';
      const results = await scanner.scan('/test/file.xyz', content);
      expect(results).toHaveLength(0);
    });
  });
});