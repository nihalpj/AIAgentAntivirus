import { execSync } from 'child_process';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('CLI Integration Tests', () => {
  const tempDir = path.join(__dirname, '../temp');

  beforeAll(async () => {
    await fs.ensureDir(tempDir);
  });

  afterEach(async () => {
    await fs.emptyDir(tempDir);
  });

  afterAll(async () => {
    await fs.remove(tempDir);
  });

  describe('aiav scan', () => {
    it('should show help', () => {
      const output = execSync('npm run dev -- scan --help', { encoding: 'utf-8' });
      expect(output).toContain('Scan AI agent files');
    });

    it('should scan a directory with JSON files', async () => {
      const testFile = path.join(tempDir, 'test.json');
      await fs.writeJson(testFile, {
        apiKey: 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef'
      });

      let output = '';
      try {
        output = execSync(`npm run dev -- scan ${tempDir}`, { encoding: 'utf-8', stdio: 'pipe' });
      } catch (error: any) {
        // Scan returns exit code 1 when issues are found
        output = error.stdout || error.toString();
      }

      expect(output).toContain('hardcoded-secret');
    });

    it('should handle empty directories', async () => {
      const emptyDir = path.join(tempDir, 'empty');
      await fs.ensureDir(emptyDir);

      const output = execSync(`npm run dev -- scan ${emptyDir}`, { encoding: 'utf-8' });
      expect(output).toContain('No security issues found');
    });
  });
});