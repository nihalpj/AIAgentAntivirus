import { FileWatcher } from '../../../src/watcher/file-watcher';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';

describe('FileWatcher', () => {
  let watcher: FileWatcher;
  let tempDir: string;

  beforeEach(async () => {
    watcher = new FileWatcher();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'aiav-test-'));
  });

  afterEach(async () => {
    watcher.stop();
    if (await fs.pathExists(tempDir)) {
      await fs.remove(tempDir);
    }
  });

  describe('watch', () => {
    it('should start watching a directory', (done) => {
      const addSpy = jest.fn();
      watcher.on('add', addSpy);

      watcher.watch(tempDir);

      // Allow watcher to start
      setTimeout(() => {
        expect(addSpy).not.toHaveBeenCalled();
        done();
      }, 100);
    });

    it('should emit add event when file is added', (done) => {
      const addSpy = jest.fn();
      watcher.on('add', addSpy);

      watcher.watch(tempDir);

      setTimeout(async () => {
        const testFile = path.join(tempDir, 'test.txt');
        await fs.writeFile(testFile, 'test content');

        setTimeout(() => {
          expect(addSpy).toHaveBeenCalledWith(expect.stringContaining('test.txt'));
          done();
        }, 200);
      }, 100);
    }, 5000);

    it('should emit change event when file is modified', (done) => {
      const changeSpy = jest.fn();
      watcher.on('change', changeSpy);

      watcher.watch(tempDir);

      setTimeout(async () => {
        const testFile = path.join(tempDir, 'test.txt');
        await fs.writeFile(testFile, 'initial content');

        setTimeout(async () => {
          await fs.writeFile(testFile, 'modified content');

          setTimeout(() => {
            expect(changeSpy).toHaveBeenCalledWith(expect.stringContaining('test.txt'));
            done();
          }, 200);
        }, 200);
      }, 100);
    }, 10000);

    it('should emit unlink event when file is deleted', (done) => {
      const unlinkSpy = jest.fn();
      watcher.on('unlink', unlinkSpy);

      watcher.watch(tempDir);

      setTimeout(async () => {
        const testFile = path.join(tempDir, 'test.txt');
        await fs.writeFile(testFile, 'test content');

        setTimeout(async () => {
          await fs.unlink(testFile);

          setTimeout(() => {
            expect(unlinkSpy).toHaveBeenCalledWith(expect.stringContaining('test.txt'));
            done();
          }, 200);
        }, 200);
      }, 100);
    }, 10000);

    it('should stop watching when stop is called', (done) => {
      const changeSpy = jest.fn();
      watcher.on('change', changeSpy);

      watcher.watch(tempDir);

      setTimeout(async () => {
        const testFile = path.join(tempDir, 'test.txt');
        await fs.writeFile(testFile, 'initial content');

        setTimeout(async () => {
          watcher.stop();
          await fs.writeFile(testFile, 'modified content');

          setTimeout(() => {
            // Change spy should only be called once (initial write)
            expect(changeSpy).toHaveBeenCalledTimes(0);
            done();
          }, 500);
        }, 200);
      }, 100);
    }, 10000);

    it('should restart watching when watch is called again', (done) => {
      const changeSpy = jest.fn();
      watcher.on('change', changeSpy);

      watcher.watch(tempDir);

      setTimeout(async () => {
        const testFile = path.join(tempDir, 'test.txt');
        await fs.writeFile(testFile, 'initial content');

        setTimeout(async () => {
          watcher.stop();
          watcher.watch(tempDir);

          setTimeout(async () => {
            await fs.writeFile(testFile, 'modified content');

            setTimeout(() => {
              expect(changeSpy).toHaveBeenCalledWith(expect.stringContaining('test.txt'));
              done();
            }, 200);
          }, 200);
        }, 200);
      }, 100);
    }, 15000);

    it('should watch multiple paths', (done) => {
      const addSpy = jest.fn();
      watcher.on('add', addSpy);

      const tempDir2 = path.join(tempDir, 'subdir2');
      const tempDir3 = path.join(tempDir, 'subdir3');

      fs.mkdirSync(tempDir2);
      fs.mkdirSync(tempDir3);

      watcher.watch([tempDir2, tempDir3]);

      setTimeout(async () => {
        const testFile1 = path.join(tempDir2, 'test1.txt');
        const testFile2 = path.join(tempDir3, 'test2.txt');
        await fs.writeFile(testFile1, 'content1');
        await fs.writeFile(testFile2, 'content2');

        setTimeout(() => {
          expect(addSpy).toHaveBeenCalledTimes(2);
          done();
        }, 200);
      }, 100);
    }, 10000);

    it('should respect ignoreInitial option', (done) => {
      const addSpy = jest.fn();
      watcher.on('add', addSpy);

      // Create a file before watching
      const testFile = path.join(tempDir, 'preexisting.txt');
      fs.writeFileSync(testFile, 'preexisting content');

      watcher.watch(tempDir, { ignoreInitial: true });

      setTimeout(() => {
        expect(addSpy).not.toHaveBeenCalled();
        done();
      }, 300);
    }, 5000);
  });
});
