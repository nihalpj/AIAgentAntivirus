#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { watchCommand } from './commands/watch';

const program = new Command();

program
  .name('aiav')
  .description('AIAgentAntivirus - Security scanner for AI agent files')
  .version('0.0.1');

program.addCommand(scanCommand);
program.addCommand(watchCommand);

program.parse();
