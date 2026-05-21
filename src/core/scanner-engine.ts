import { Scanner, ScanResult, ScannerType } from './scanner-interface';
import { ResultAggregator } from './result';

export interface ScannerEngineOptions {
  enabledScanners?: ScannerType[];
  parallelism?: number;
}

export class ScannerEngine {
  private scanners: Map<ScannerType, Scanner> = new Map();
  private aggregator: ResultAggregator;
  private parallelism: number;

  constructor(options: ScannerEngineOptions = {}) {
    this.aggregator = new ResultAggregator();
    this.parallelism = options.parallelism || 1;
  }

  registerScanner(scanner: Scanner): void {
    this.scanners.set(scanner.type, scanner);
  }

  async scanFiles(
    files: Array<{ path: string; content: string }>,
    options: ScannerEngineOptions = {}
  ): Promise<{ results: ScanResult[]; exitCode: number }> {
    const enabledTypes = options.enabledScanners || Array.from(this.scanners.keys());
    const filesToScan = files.filter(f => f);

    await this.processFiles(filesToScan, enabledTypes);

    return {
      results: this.aggregator.getResults(),
      exitCode: this.aggregator.getExitCode()
    };
  }

  private async processFiles(
    files: Array<{ path: string; content: string }>,
    enabledTypes: ScannerType[]
  ): Promise<void> {
    if (this.parallelism === 1) {
      for (const file of files) {
        await this.scanFile(file, enabledTypes);
      }
    } else {
      const chunks = this.chunkArray(files, this.parallelism);
      await Promise.all(
        chunks.map(chunk => this.processChunk(chunk, enabledTypes))
      );
    }
  }

  private async processChunk(
    files: Array<{ path: string; content: string }>,
    enabledTypes: ScannerType[]
  ): Promise<void> {
    for (const file of files) {
      await this.scanFile(file, enabledTypes);
    }
  }

  private async scanFile(
    file: { path: string; content: string },
    enabledTypes: ScannerType[]
  ): Promise<void> {
    for (const type of enabledTypes) {
      const scanner = this.scanners.get(type);
      if (scanner) {
        try {
          const results = await scanner.scan(file.path, file.content);
          this.aggregator.addAll(results);
        } catch (error) {
          console.warn(`Scanner ${type} failed for ${file.path}:`, error);
        }
      }
    }
  }

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  getAggregator(): ResultAggregator {
    return this.aggregator;
  }

  getScannerCount(): number {
    return this.scanners.size;
  }
}