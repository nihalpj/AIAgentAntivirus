import { Severity } from './severity';

export interface ScanResult {
  id: string;
  filePath: string;
  lineNumber: number;
  severity: Severity;
  category: ThreatCategory;
  description: string;
  evidence?: string;
  suggestion?: string;
  scannerType: ScannerType;
}

export interface Scanner {
  readonly name: string;
  readonly type: ScannerType;
  scan(filePath: string, content: string): Promise<ScanResult[]>;
}

export enum ScannerType {
  Pattern = 'pattern',
  AST = 'ast',
  LLM = 'llm',
  Hybrid = 'hybrid'
}

export enum ThreatCategory {
  PromptInjection = 'prompt-injection',
  MaliciousCommand = 'malicious-command',
  HardcodedSecret = 'hardcoded-secret',
  UnsafeExecution = 'unsafe-execution',
  Obfuscation = 'obfuscation',
  SocialEngineering = 'social-engineering',
  DataExfiltration = 'data-exfiltration',
  ResourceAbuse = 'resource-abuse',
  Other = 'other'
}