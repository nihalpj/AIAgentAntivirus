import * as path from 'path';
import * as micromatch from 'micromatch';
import * as fs from 'fs-extra';

export interface FilterOptions {
  extensions?: string[];
  excludePatterns?: string[];
  maxSizeMB?: number;
}

export class FileFilter {
  private readonly allowedExtensions: Set<string>;
  private readonly excludePatterns: string[];
  private readonly maxSizeBytes: number;

  constructor(options: FilterOptions = {}) {
    this.allowedExtensions = new Set(
      (options.extensions || ['json', 'py', 'js', 'ts', 'jsx', 'tsx', 'md']).map(ext =>
        ext.startsWith('.') ? ext : `.${ext}`
      )
    );
    this.excludePatterns = options.excludePatterns || [];
    this.maxSizeBytes = (options.maxSizeMB || 10) * 1024 * 1024;
  }

  async shouldInclude(filePath: string): Promise<boolean> {
    const ext = path.extname(filePath).toLowerCase();

    if (!this.allowedExtensions.has(ext)) {
      return false;
    }

    if (this.isExcluded(filePath)) {
      return false;
    }

    const stats = await fs.stat(filePath);

    if (stats.size > this.maxSizeBytes) {
      return false;
    }

    if (stats.isDirectory()) {
      return false;
    }

    return true;
  }

  private isExcluded(filePath: string): boolean {
    if (this.excludePatterns.length === 0) {
      return false;
    }
    return micromatch.isMatch(filePath, this.excludePatterns);
  }

  getAllowedExtensions(): string[] {
    return Array.from(this.allowedExtensions);
  }

  getMaxSizeBytes(): number {
    return this.maxSizeBytes;
  }
}