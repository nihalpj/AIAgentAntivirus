#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan';

const program = new Command();

program
  .name('aiav')
  .description('AIAgentAntivirus - Security scanner for AI agent files')
  .version('0.0.1');

program.addCommand(scanCommand);

program.parse();
