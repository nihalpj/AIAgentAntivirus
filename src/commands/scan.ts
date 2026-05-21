import { Command } from 'commander';
import * as fs from 'fs-extra';
import * as os from 'os';
import { FileWalker } from '../walker/file-walker';
import { PatternScanner } from '../scanners/pattern-scanner';
import { ScannerEngine } from '../core/scanner-engine';
import { ASTScanner } from '../scanners/ast-scanner';
import { LLMScanner } from '../scanners/llm-scanner';
import { ConsoleFormatter } from '../formatters/console-formatter';
import { JSONFormatter } from '../formatters/json-formatter';
import { HTMLFormatter } from '../formatters/html-formatter';
import { SARIFFormatter } from '../formatters/sarif-formatter';
import { Formatter } from '../formatters/formatter-interface';

export const scanCommand = new Command('scan')
  .description('Scan AI agent files for security threats')
  .argument('[path]', 'Path to scan (default: auto-detect platform paths)')
  .option('--platform <name>', 'Target platform (claude, openai, google, cursor, all)', 'all')
  .option('--ext <extensions>', 'File extensions (comma-separated)', 'json,py,js,ts,jsx,tsx,md')
  .option('--exclude <patterns>', 'Exclude patterns (comma-separated)', '')
  .option('--format <type>', 'Output format: console, json, html, sarif', 'console')
  .option('--llm-provider <name>', 'LLM provider for AI scanning (anthropic, openai)', '')
  .option('--llm-api-key <key>', 'LLM API key (overrides env vars)', '')
  .option('--verbose', 'Enable verbose logging', false)
  .option('--workers <number>', 'Number of parallel workers', String(os.cpus().length))
  .action(async (path, options) => {
    const startTime = Date.now();

    try {
      const extensions = options.ext.split(',').map((e: string) => e.trim());
      const excludePatterns = options.exclude
        ? options.exclude.split(',').map((e: string) => e.trim())
        : undefined;

      const walker = new FileWalker({
        platform: options.platform,
        extensions,
        excludePatterns,
      });

      if (options.verbose) {
        console.log(`Scanning path: ${path || 'auto-detected'}`);
      }

      const files = await walker.walk(path);

      if (options.verbose) {
        console.log(`Found ${files.length} files to scan`);
      }

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

        // Set API key if provided via CLI
        if (options.llmApiKey) {
          llmScanner.setApiKey(options.llmApiKey);
        }

        // Check if API key is configured
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

      const results: Array<{ path: string; content: string }> = [];

      for (const file of files) {
        const content = await fs.readFile(file.path, 'utf-8');
        results.push({ path: file.path, content });

        if (options.verbose) {
          console.log(`Scanned: ${file.path}`);
        }
      }

      const scanResult = await engine.scanFiles(results);
      const aggregator = engine.getAggregator();

      const duration = Date.now() - startTime;
      const summary = aggregator.getSummary(files.length, duration);

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
      const output = formatter.formatResults(scanResult.results, summary);

      console.log(output);

      process.exit(scanResult.exitCode);
    } catch (error) {
      console.error('Scan failed:', error);
      process.exit(2);
    }
  });
