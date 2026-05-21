import { FileWalker } from '../../../src/walker/file-walker';
import * as fs from 'fs-extra';

jest.mock('fs-extra');

const mockCwd = jest.fn();
Object.defineProperty(process, 'cwd', {
  value: mockCwd,
  writable: true,
});

describe('FileWalker', () => {
  let walker: FileWalker;

  beforeEach(() => {
    jest.clearAllMocks();
    mockCwd.mockReturnValue('/workspaces/AIAgentAntivirus');
  });

  describe('walk', () => {
    it('should walk directory and return files', async () => {
      (fs.readdir as any).mockResolvedValue([
        { name: 'file1.js', isDirectory: () => false },
        { name: 'file2.json', isDirectory: () => false },
      ]);
      // FileFilter calls fs.stat for each file, then walkDirectory calls it again
      (fs.stat as any)
        .mockResolvedValueOnce({ size: 1000, isDirectory: () => false }) // file1.js filter check
        .mockResolvedValueOnce({ size: 2000, isDirectory: () => false }) // file2.json filter check
        .mockResolvedValueOnce({ size: 1000, isDirectory: () => false }) // file1.js walkDirectory
        .mockResolvedValueOnce({ size: 2000, isDirectory: () => false }); // file2.json walkDirectory

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(2);
      expect(files[0].path).toContain('file1.js');
      expect(files[1].path).toContain('file2.json');
    });

    it('should skip excluded directories', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'node_modules', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should handle read errors gracefully', async () => {
      (fs.readdir as any).mockRejectedValue(new Error('Permission denied'));

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(0);
    });

    it('should use custom paths when provided', async () => {
      (fs.readdir as any).mockResolvedValue([{ name: 'file.js', isDirectory: () => false }]);
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker({ customPaths: ['/custom/path'] });
      await walker.walk();

      expect(fs.readdir).toHaveBeenCalledWith('/custom/path', { withFileTypes: true });
    });

    it('should skip .git directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: '.git', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip dist directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'dist', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip build directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'build', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip coverage directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'coverage', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip .next directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: '.next', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip .nuxt directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: '.nuxt', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip target directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'target', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip bin directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'bin', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should skip obj directory', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'obj', isDirectory: () => true },
          ]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].path).toContain('file.js');
    });

    it('should handle nested directories', async () => {
      (fs.readdir as any).mockImplementation((dir: string) => {
        if (dir === '/test/path') {
          return Promise.resolve([
            { name: 'file.js', isDirectory: () => false },
            { name: 'src', isDirectory: () => true },
          ]);
        }
        if (dir === '/test/path/src') {
          return Promise.resolve([{ name: 'nested.js', isDirectory: () => false }]);
        }
        return Promise.resolve([]);
      });
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(2);
      expect(files.some((f) => f.path.includes('file.js'))).toBe(true);
      expect(files.some((f) => f.path.includes('nested.js'))).toBe(true);
    });

    it('should deduplicate files', async () => {
      (fs.readdir as any).mockResolvedValue([{ name: 'file.js', isDirectory: () => false }]);
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');
      const files2 = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files2).toHaveLength(1);
    });

    it('should include file size in FileEntry', async () => {
      (fs.readdir as any).mockResolvedValue([{ name: 'file.js', isDirectory: () => false }]);
      (fs.stat as any).mockResolvedValue({ size: 1234, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].size).toBe(1234);
    });

    it('should include relative path in FileEntry', async () => {
      (fs.readdir as any).mockResolvedValue([{ name: 'file.js', isDirectory: () => false }]);
      (fs.stat as any).mockResolvedValue({ size: 1000, isDirectory: () => false });

      walker = new FileWalker();
      const files = await walker.walk('/test/path');

      expect(files).toHaveLength(1);
      expect(files[0].relativePath).toBeDefined();
      expect(files[0].relativePath).toContain('file.js');
    });
  });
});
