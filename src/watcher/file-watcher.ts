import chokidar from 'chokidar';
import { EventEmitter } from 'events';

export interface WatchOptions {
  ignoreInitial?: boolean;
  usePolling?: boolean;
  interval?: number;
}

export class FileWatcher extends EventEmitter {
  private watcher: chokidar.FSWatcher | null = null;

  constructor() {
    super();
  }

  watch(paths: string | string[], options: WatchOptions = {}): void {
    if (this.watcher) {
      this.stop();
    }

    this.watcher = chokidar.watch(paths, {
      ignored: /(^|[\/\\])\../,
      persistent: true,
      ignoreInitial: options.ignoreInitial ?? false,
      usePolling: options.usePolling ?? false,
      interval: options.interval ?? 100,
    });

    this.watcher
      .on('add', (path) => this.emit('add', path))
      .on('change', (path) => this.emit('change', path))
      .on('unlink', (path) => this.emit('unlink', path))
      .on('error', (error) => this.emit('error', error));
  }

  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }
}
