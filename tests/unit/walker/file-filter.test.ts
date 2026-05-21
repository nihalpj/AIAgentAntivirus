import * as fs from 'fs-extra';
import * as path from 'path';
import { FileFilter } from '../../../src/walker/file-filter';

describe('FileFilter', () => {
  const testDir = path.join(__dirname, 'test-files');

  beforeEach(async () => {
    await fs.ensureDir(testDir);
    await fs.writeFile(path.join(testDir, 'file.js'), 'console.log("test");');
    await fs.writeFile(path.join(testDir, 'file.ts'), 'const x = 1;');
    await fs.writeFile(path.join(testDir, 'file.py'), 'print("test");');
    await fs.writeFile(path.join(testDir, 'file.json'), '{"test": true}');
    await fs.writeFile(path.join(testDir, 'file.md'), '# Test');
    await fs.writeFile(path.join(testDir, 'file.jsx'), 'const App = () => <div />;');
    await fs.writeFile(path.join(testDir, 'file.tsx'), 'const App = () => <div />;');
    await fs.writeFile(path.join(testDir, 'file.txt'), 'plain text');
    await fs.writeFile(path.join(testDir, 'file.exe'), 'binary content');
  });

  afterEach(async () => {
    await fs.remove(testDir);
  });

  describe('Extension filtering', () => {
    it('should accept JavaScript files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.js'));
      expect(result).toBe(true);
    });

    it('should accept TypeScript files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.ts'));
      expect(result).toBe(true);
    });

    it('should accept JSON files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.json'));
      expect(result).toBe(true);
    });

    it('should accept Markdown files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.md'));
      expect(result).toBe(true);
    });

    it('should accept JSX files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.jsx'));
      expect(result).toBe(true);
    });

    it('should accept TSX files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.tsx'));
      expect(result).toBe(true);
    });

    it('should accept Python files', async () => {
      const filter = new FileFilter();
      const result = await filter.shouldInclude(path.join(testDir, 'file.py'));
      expect(result).toBe(true);
    });

    it('should reject files with non-allowed extensions', async () => {
      const filter = new FileFilter();
      const txtResult = await filter.shouldInclude(path.join(testDir, 'file.txt'));
      const exeResult = await filter.shouldInclude(path.join(testDir, 'file.exe'));
      expect(txtResult).toBe(false);
      expect(exeResult).toBe(false);
    });

    it('should use custom extension list when provided', async () => {
      const filter = new FileFilter({ extensions: ['js', 'ts'] });
      const jsResult = await filter.shouldInclude(path.join(testDir, 'file.js'));
      const tsResult = await filter.shouldInclude(path.join(testDir, 'file.ts'));
      const jsonResult = await filter.shouldInclude(path.join(testDir, 'file.json'));
      const pyResult = await filter.shouldInclude(path.join(testDir, 'file.py'));

      expect(jsResult).toBe(true);
      expect(tsResult).toBe(true);
      expect(jsonResult).toBe(false);
      expect(pyResult).toBe(false);
    });

    it('should handle extensions with and without leading dot', async () => {
      const filterWithDot = new FileFilter({ extensions: ['.js', 'ts'] });
      const jsResult = await filterWithDot.shouldInclude(path.join(testDir, 'file.js'));
      const tsResult = await filterWithDot.shouldInclude(path.join(testDir, 'file.ts'));

      expect(jsResult).toBe(true);
      expect(tsResult).toBe(true);
    });

    it('should return list of allowed extensions', () => {
      const filter = new FileFilter({ extensions: ['js', 'ts'] });
      const extensions = filter.getAllowedExtensions();

      expect(extensions).toContain('.js');
      expect(extensions).toContain('.ts');
      expect(extensions.length).toBe(2);
    });
  });

  describe('Pattern exclusion', () => {
    it('should exclude files matching patterns', async () => {
      await fs.writeFile(path.join(testDir, 'test.js'), '// test file');
      await fs.writeFile(path.join(testDir, 'prod.js'), '// prod file');

      const filter = new FileFilter({
        excludePatterns: ['**/test.js'],
      });

      const testResult = await filter.shouldInclude(path.join(testDir, 'test.js'));
      const prodResult = await filter.shouldInclude(path.join(testDir, 'prod.js'));

      expect(testResult).toBe(false);
      expect(prodResult).toBe(true);
    });

    it('should exclude files using glob patterns', async () => {
      await fs.writeFile(path.join(testDir, 'file.test.js'), '// test file');
      await fs.writeFile(path.join(testDir, 'file.prod.js'), '// prod file');

      const filter = new FileFilter({
        excludePatterns: ['**/*.test.js'],
      });

      const testResult = await filter.shouldInclude(path.join(testDir, 'file.test.js'));
      const prodResult = await filter.shouldInclude(path.join(testDir, 'file.prod.js'));

      expect(testResult).toBe(false);
      expect(prodResult).toBe(true);
    });

    it('should exclude files in node_modules directory', async () => {
      const nodeModulesDir = path.join(testDir, 'node_modules', 'package');
      await fs.ensureDir(nodeModulesDir);
      await fs.writeFile(path.join(nodeModulesDir, 'index.js'), '// library file');

      const filter = new FileFilter({
        excludePatterns: ['**/node_modules/**'],
      });

      const result = await filter.shouldInclude(path.join(nodeModulesDir, 'index.js'));
      expect(result).toBe(false);
    });

    it('should exclude files matching any of multiple patterns', async () => {
      await fs.writeFile(path.join(testDir, 'file.test.js'), '// test file');
      await fs.writeFile(path.join(testDir, 'file.spec.js'), '// spec file');
      await fs.writeFile(path.join(testDir, 'file.prod.js'), '// prod file');

      const filter = new FileFilter({
        excludePatterns: ['**/*.test.js', '**/*.spec.js'],
      });

      const testResult = await filter.shouldInclude(path.join(testDir, 'file.test.js'));
      const specResult = await filter.shouldInclude(path.join(testDir, 'file.spec.js'));
      const prodResult = await filter.shouldInclude(path.join(testDir, 'file.prod.js'));

      expect(testResult).toBe(false);
      expect(specResult).toBe(false);
      expect(prodResult).toBe(true);
    });

    it('should accept all files when no exclusion patterns are provided', async () => {
      await fs.writeFile(path.join(testDir, 'test.js'), '// test file');

      const filter = new FileFilter();

      const result = await filter.shouldInclude(path.join(testDir, 'test.js'));
      expect(result).toBe(true);
    });
  });

  describe('Size filtering', () => {
    it('should reject files larger than max size', async () => {
      const largeContent = 'x'.repeat(15 * 1024 * 1024); // 15 MB
      await fs.writeFile(path.join(testDir, 'large.js'), largeContent);

      const filter = new FileFilter({ maxSizeMB: 10 });

      const result = await filter.shouldInclude(path.join(testDir, 'large.js'));
      expect(result).toBe(false);
    });

    it('should accept files smaller than max size', async () => {
      const smallContent = 'x'.repeat(1024); // 1 KB
      await fs.writeFile(path.join(testDir, 'small.js'), smallContent);

      const filter = new FileFilter({ maxSizeMB: 10 });

      const result = await filter.shouldInclude(path.join(testDir, 'small.js'));
      expect(result).toBe(true);
    });

    it('should accept files exactly at max size', async () => {
      const exactContent = 'x'.repeat(10 * 1024 * 1024); // 10 MB
      await fs.writeFile(path.join(testDir, 'exact.js'), exactContent);

      const filter = new FileFilter({ maxSizeMB: 10 });

      const result = await filter.shouldInclude(path.join(testDir, 'exact.js'));
      expect(result).toBe(true);
    });

    it('should return max size in bytes', () => {
      const filter = new FileFilter({ maxSizeMB: 5 });
      const maxBytes = filter.getMaxSizeBytes();

      expect(maxBytes).toBe(5 * 1024 * 1024);
    });

    it('should use default max size of 10 MB', () => {
      const filter = new FileFilter();
      const maxBytes = filter.getMaxSizeBytes();

      expect(maxBytes).toBe(10 * 1024 * 1024);
    });
  });

  describe('Directory handling', () => {
    it('should reject directories', async () => {
      const subDir = path.join(testDir, 'subdir');
      await fs.ensureDir(subDir);

      const filter = new FileFilter();

      const result = await filter.shouldInclude(subDir);
      expect(result).toBe(false);
    });
  });

  describe('Combined filtering', () => {
    it('should apply all filters in order', async () => {
      const largeContent = 'x'.repeat(15 * 1024 * 1024); // 15 MB
      await fs.writeFile(path.join(testDir, 'large.test.js'), largeContent);

      const filter = new FileFilter({
        extensions: ['js'],
        excludePatterns: ['**/*.test.js'],
        maxSizeMB: 10,
      });

      const result = await filter.shouldInclude(path.join(testDir, 'large.test.js'));
      expect(result).toBe(false);
    });

    it('should accept file only if it passes all filters', async () => {
      const content = 'console.log("test");';
      await fs.writeFile(path.join(testDir, 'valid.js'), content);

      const filter = new FileFilter({
        extensions: ['js'],
        excludePatterns: [],
        maxSizeMB: 10,
      });

      const result = await filter.shouldInclude(path.join(testDir, 'valid.js'));
      expect(result).toBe(true);
    });

    it('should reject file if it fails extension filter', async () => {
      const content = 'plain text';
      await fs.writeFile(path.join(testDir, 'file.txt'), content);

      const filter = new FileFilter({ extensions: ['js'] });

      const result = await filter.shouldInclude(path.join(testDir, 'file.txt'));
      expect(result).toBe(false);
    });

    it('should reject file if it fails exclusion filter', async () => {
      const content = 'console.log("test");';
      await fs.writeFile(path.join(testDir, 'file.test.js'), content);

      const filter = new FileFilter({
        extensions: ['js'],
        excludePatterns: ['**/*.test.js'],
      });

      const result = await filter.shouldInclude(path.join(testDir, 'file.test.js'));
      expect(result).toBe(false);
    });

    it('should reject file if it fails size filter', async () => {
      const largeContent = 'x'.repeat(15 * 1024 * 1024);
      await fs.writeFile(path.join(testDir, 'large.js'), largeContent);

      const filter = new FileFilter({
        extensions: ['js'],
        maxSizeMB: 10,
      });

      const result = await filter.shouldInclude(path.join(testDir, 'large.js'));
      expect(result).toBe(false);
    });
  });
});
