import { Command } from 'commander';
import { FileWatcher } from '../watcher/file-watcher';
import { Scheduler } from '../watcher/scheduler';
import { AlertSystem } from '../watcher/alert-system';
import { FileWalker } from '../walker/file-walker';
import { PatternScanner } from '../scanners/pattern-scanner';
import { ASTScanner } from '../scanners/ast-scanner';
import { LLMScanner } from '../scanners/llm-scanner';
import { ScannerEngine } from '../core/scanner-engine';
import { ConsoleFormatter } from '../formatters/console-formatter';
import { Formatter } from '../formatters/formatter-interface';
import { JSONFormatter } from '../formatters/json-formatter';
import { HTMLFormatter } from '../formatters/html-formatter';
import { SARIFFormatter } from '../formatters/sarif-formatter';
import * as fs from 'fs-extra';
import * as os from 'os';

export const watchCommand = new Command('watch')
  .description('Watch directories for changes and scan continuously')
  .argument('[path]', 'Path to watch (default: current directory)', '.')
  .option('--schedule <cron>', 'Cron expression for scheduled scans (e.g., "0 * * * *" for hourly)')
  .option('--webhook <url>', 'Webhook URL for alerts')
  .option('--webhook-method <method>', 'Webhook HTTP method', 'POST')
  .option('--polling', 'Use polling instead of native file watching', false)
  .option('--interval <ms>', 'Polling interval in milliseconds', '1000')
  .option('--platform <name>', 'Target platform (claude, openai, google, cursor, all)', 'all')
  .option('--ext <extensions>', 'File extensions (comma-separated)', 'json,py,js,ts,jsx,tsx,md')
  .option('--exclude <patterns>', 'Exclude patterns (comma-separated)', '')
  .option('--format <type>', 'Output format: console, json, html, sarif', 'console')
  .option('--llm-provider <name>', 'LLM provider for AI scanning (anthropic, openai)', '')
  .option('--llm-api-key <key>', 'LLM API key (overrides env vars)', '')
  .option('--verbose', 'Enable verbose logging', false)
  .option('--workers <number>', 'Number of parallel workers', String(os.cpus().length))
  .action(async (path, options) => {
    const extensions = options.ext.split(',').map((e: string) => e.trim());
    const excludePatterns = options.exclude
      ? options.exclude.split(',').map((e: string) => e.trim())
      : undefined;

    const walker = new FileWalker({
      platform: options.platform,
      extensions,
      excludePatterns,
    });

    const engine = new ScannerEngine({ parallelism: parseInt(options.workers) });
    engine.registerScanner(new PatternScanner());
    engine.registerScanner(new ASTScanner());

    // Register LLM scanner if provider is configured
    if (options.llmProvider) {
      if (options.llmProvider !== 'anthropic' && options.llmProvider !== 'openai') {
        console.error(
          `Invalid LLM provider: ${options.llmProvider}. Valid options: anthropic, openai`
        );
        process.exit(2);
      }

      const llmScanner = new LLMScanner(options.llmProvider as 'anthropic' | 'openai');

      if (options.llmApiKey) {
        llmScanner.setApiKey(options.llmApiKey);
      }

      const envVar = options.llmProvider === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY';

      if (!process.env[envVar] && !options.llmApiKey) {
        console.warn(
          `Warning: LLM scanner configured but ${envVar} not set and no --llm-api-key provided. LLM scans will fail.`
        );
      }

      engine.registerScanner(llmScanner);

      if (options.verbose) {
        console.log(`LLM Scanner enabled with provider: ${options.llmProvider}`);
      }
    }

    const alertSystem = new AlertSystem({
      enabled: !!options.webhook,
      webhookUrl: options.webhook,
      webhookMethod: options.webhookMethod as 'POST' | 'PUT'
    });

    const watcher = new FileWatcher();

    let formatter: Formatter;
    switch (options.format) {
      case 'json':
        formatter = new JSONFormatter();
        break;
      case 'html':
        formatter = new HTMLFormatter();
        break;
      case 'sarif':
        formatter = new SARIFFormatter();
        break;
      default:
        formatter = new ConsoleFormatter();
    }

    const runScan = async () => {
      try {
        const startTime = Date.now();

        if (options.verbose) {
          console.log(`Scanning path: ${path}`);
        }

        const files = await walker.walk(path);

        if (options.verbose) {
          console.log(`Found ${files.length} files to scan`);
        }

        const contents = await Promise.all(
          files.map(async (f) => {
            return {
              path: f.path,
              content: await fs.readFile(f.path, 'utf-8')
            };
          })
        );

        const result = await engine.scanFiles(contents);
        const aggregator = engine.getAggregator();
        const duration = Date.now() - startTime;
        const summary = aggregator.getSummary(files.length, duration);

        if (result.results.length > 0) {
          console.log(formatter.formatResults(result.results, summary));

          for (const r of result.results) {
            await alertSystem.sendAlert({
              timestamp: new Date(),
              filePath: r.filePath,
              severity: r.severity,
              category: r.category,
              description: r.description
            });
          }
        } else if (options.verbose) {
          console.log('No security issues found.');
        }
      } catch (error) {
        console.error('Scan failed:', error);
      }
    };

    // Initial scan
    console.log(`🔍 Starting watch mode on: ${path}`);
    await runScan();

    // Set up file watcher
    watcher.watch(path, {
      usePolling: options.polling,
      interval: parseInt(options.interval)
    });

    watcher.on('change', async (filePath) => {
      console.log(`\n📝 File changed: ${filePath}`);
      await runScan();
    });

    watcher.on('add', async (filePath) => {
      console.log(`\n➕ File added: ${filePath}`);
      await runScan();
    });

    watcher.on('unlink', async (filePath) => {
      console.log(`\n🗑️  File removed: ${filePath}`);
    });

    watcher.on('error', (error) => {
      console.error('Watcher error:', error);
    });

    // Set up scheduler if specified
    if (options.schedule) {
      const scheduler = new Scheduler();
      console.log(`⏰ Scheduled scans: ${options.schedule}`);
      scheduler.schedule('main', options.schedule, async () => {
        console.log('\n⏰ Running scheduled scan...');
        await runScan();
      });
    }

    console.log('👀 Watching for changes... (Press Ctrl+C to stop)');

    // Handle graceful shutdown
    const cleanup = () => {
      console.log('\n🛑 Stopping watch mode...');
      watcher.stop();
      process.exit(0);
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
  });