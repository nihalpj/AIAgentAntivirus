import * as path from 'path';
import * as fs from 'fs-extra';
import { FileFilter, FilterOptions } from './file-filter';
import { PlatformPathDetector } from './platform-paths';

export interface WalkerOptions extends FilterOptions {
  customPaths?: string[];
  platform?: string;
  respectGitignore?: boolean;
}

export interface FileEntry {
  path: string;
  relativePath: string;
  size: number;
}

export class FileWalker {
  private filter: FileFilter;
  private platformDetector: PlatformPathDetector;

  constructor(private options: WalkerOptions = {}) {
    this.filter = new FileFilter(options);
    this.platformDetector = new PlatformPathDetector();
  }

  async walk(targetPath?: string): Promise<FileEntry[]> {
    const pathsToScan = targetPath
      ? [targetPath]
      : await this.resolvePaths();

    const files: FileEntry[] = [];

    for (const scanPath of pathsToScan) {
      const found = await this.walkDirectory(scanPath);
      files.push(...found);
    }

    return this.deduplicateFiles(files);
  }

  private async resolvePaths(): Promise<string[]> {
    if (this.options.customPaths && this.options.customPaths.length > 0) {
      return this.options.customPaths;
    }

    if (this.options.platform && this.options.platform !== 'all') {
      return this.platformDetector.getPlatformPaths(
        this.options.platform as any
      );
    }

    const existingPaths = await this.platformDetector.detectExistingPaths('all');
    return existingPaths.length > 0 ? existingPaths : [process.cwd()];
  }

  private async walkDirectory(dirPath: string): Promise<FileEntry[]> {
    const files: FileEntry[] = [];

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
          if (!this.shouldSkipDirectory(fullPath)) {
            const subFiles = await this.walkDirectory(fullPath);
            files.push(...subFiles);
          }
        } else if (await this.filter.shouldInclude(fullPath)) {
          const stats = await fs.stat(fullPath);
          files.push({
            path: fullPath,
            relativePath: path.relative(process.cwd(), fullPath),
            size: stats.size
          });
        }
      }
    } catch (error) {
      console.warn(`Warning: Could not read directory ${dirPath}: ${error}`);
    }

    return files;
  }

  private shouldSkipDirectory(dirPath: string): boolean {
    const baseName = path.basename(dirPath);
    const skipDirs = new Set([
      'node_modules',
      '.git',
      'dist',
      'build',
      'coverage',
      '.next',
      '.nuxt',
      'target',
      'bin',
      'obj'
    ]);

    if (skipDirs.has(baseName)) {
      return true;
    }

    if (this.options.excludePatterns) {
      const micromatch = require('micromatch');
      return micromatch.isMatch(dirPath, this.options.excludePatterns);
    }

    return false;
  }

  private deduplicateFiles(files: FileEntry[]): FileEntry[] {
    const seen = new Set<string>();
    return files.filter(f => {
      if (seen.has(f.path)) {
        return false;
      }
      seen.add(f.path);
      return true;
    });
  }
}