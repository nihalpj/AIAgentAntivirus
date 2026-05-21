import { PlatformPathDetector } from '../../../src/walker/platform-paths';
import * as os from 'os';
import * as fs from 'fs-extra';

jest.mock('os');
jest.mock('fs-extra');

describe('PlatformPathDetector', () => {
  let detector: PlatformPathDetector;

  beforeEach(() => {
    jest.clearAllMocks();
    (os.platform as jest.Mock).mockReturnValue('linux');
    (os.homedir as jest.Mock).mockReturnValue('/home/user');
    detector = new PlatformPathDetector();
  });

  describe('getPlatformPaths', () => {
    it('should return all paths when platform is "all"', () => {
      const paths = detector.getPlatformPaths('all');
      expect(paths.length).toBeGreaterThan(0);
      expect(paths).toContain('/home/user/.claude');
    });

    it('should return claude-specific paths', () => {
      const paths = detector.getPlatformPaths('claude');
      expect(paths).toContain('/home/user/.claude');
      expect(paths).toContain('/home/user/.config/Claude');
    });

    it('should expand ~ to home directory', () => {
      const paths = detector.getPlatformPaths('claude');
      expect(paths).not.toContain('~');
      expect(paths.some((p) => p.startsWith('/home/user'))).toBe(true);
    });

    it('should handle Windows paths', () => {
      (os.platform as jest.Mock).mockReturnValue('win32');
      (os.homedir as jest.Mock).mockReturnValue('C:\\Users\\test');
      detector = new PlatformPathDetector();

      const paths = detector.getPlatformPaths('claude');
      expect(paths).toContain('C:\\Users\\test\\AppData\\Roaming\\Claude');
    });
  });

  describe('detectExistingPaths', () => {
    it('should return only existing paths', async () => {
      (fs.pathExists as jest.Mock)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(true);

      const paths = await detector.detectExistingPaths('claude');
      expect(paths.length).toBe(2);
    });
  });
});
