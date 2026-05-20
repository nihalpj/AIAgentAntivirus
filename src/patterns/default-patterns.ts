import { ThreatCategory } from '../core/scanner-interface';
import { Severity } from '../core/severity';

export interface PatternRule {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: Severity;
  pattern: RegExp | string;
  description: string;
  suggestion: string;
}

export const DEFAULT_PATTERNS: PatternRule[] = [
  {
    id: 'prompt-injection-1',
    name: 'Direct Prompt Injection',
    category: ThreatCategory.PromptInjection,
    severity: Severity.High,
    pattern:
      /(?:ignore|disregard|forget).*(?:previous|above|earlier).*(?:instruction|prompt|command)/i,
    description: 'Possible prompt injection attempt detected',
    suggestion: 'Validate and sanitize all user inputs before processing',
  },
  {
    id: 'prompt-injection-2',
    name: 'Jailbreak Pattern',
    category: ThreatCategory.PromptInjection,
    severity: Severity.Critical,
    pattern: /(?:jailbreak|bypass|override|circumvent).*(?:restriction|filter|safety|guardrail)/i,
    description: 'Jailbreak attempt detected',
    suggestion: 'Implement robust input validation and content filtering',
  },
  {
    id: 'secret-api-key',
    name: 'Hardcoded API Key',
    category: ThreatCategory.HardcodedSecret,
    severity: Severity.High,
    pattern:
      /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['"\s]*[:=]['"\s]*[a-zA-Z0-9_-]{20,}/i,
    description: 'Hardcoded API key detected',
    suggestion: 'Use environment variables or secret management for API keys',
  },
  {
    id: 'dangerous-eval',
    name: 'Dangerous eval() Usage',
    category: ThreatCategory.UnsafeExecution,
    severity: Severity.High,
    pattern: /eval\s*\(/i,
    description: 'Use of eval() function detected',
    suggestion: 'Avoid eval() - use safer alternatives like JSON.parse() or function constructors',
  },
  {
    id: 'dangerous-exec',
    name: 'Dangerous exec() Usage',
    category: ThreatCategory.UnsafeExecution,
    severity: Severity.High,
    pattern: /exec\s*\(\s*(?![`].*?\$\{)/i,
    description: 'Use of exec() function detected',
    suggestion: 'Use subprocess with proper argument escaping instead',
  },
  {
    id: 'command-injection',
    name: 'Command Injection Risk',
    category: ThreatCategory.MaliciousCommand,
    severity: Severity.Critical,
    pattern: /(?:os\.system|subprocess\.call|exec|spawn|child_process\.exec)\s*\(\s*["'`].*?\$\{/,
    description: 'Possible command injection via string interpolation',
    suggestion: 'Use parameterized commands or proper input sanitization',
  },
  {
    id: 'obfuscated-code',
    name: 'Code Obfuscation',
    category: ThreatCategory.Obfuscation,
    severity: Severity.Medium,
    pattern: /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i,
    description: 'Obfuscated code detected (hex/unicode escapes)',
    suggestion: 'Review code - obfuscation may hide malicious intent',
  },
  {
    id: 'base64-suspicious',
    name: 'Suspicious Base64',
    category: ThreatCategory.Obfuscation,
    severity: Severity.Medium,
    pattern: /atob\(|btoa\(/i,
    description: 'Base64 encoding/decoding detected',
    suggestion: 'Verify the legitimacy of base64 operations',
  },
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration Pattern',
    category: ThreatCategory.DataExfiltration,
    severity: Severity.High,
    pattern:
      /(?:fetch|axios|http\.request|XMLHttpRequest).*?(?:exfiltrate|leak|steal|dump|export).*?(?:data|token|credential|secret)/i,
    description: 'Possible data exfiltration attempt',
    suggestion: 'Review network requests for suspicious data transfers',
  },
  {
    id: 'social-engineering',
    name: 'Social Engineering Pattern',
    category: ThreatCategory.SocialEngineering,
    severity: Severity.Medium,
    pattern: /(?:urgent|emergency|immediate).*(?:action|required|needed|verify)/i,
    description: 'Possible social engineering attempt',
    suggestion: 'Be cautious of urgent requests - verify through official channels',
  },
];

export class PatternLibrary {
  private patterns: Map<string, PatternRule>;

  constructor(customPatterns: PatternRule[] = []) {
    this.patterns = new Map();

    DEFAULT_PATTERNS.forEach((p) => this.addPattern(p));
    customPatterns.forEach((p) => this.addPattern(p));
  }

  addPattern(pattern: PatternRule): void {
    this.patterns.set(pattern.id, pattern);
  }

  getPattern(id: string): PatternRule | undefined {
    return this.patterns.get(id);
  }

  getAllPatterns(): PatternRule[] {
    return Array.from(this.patterns.values());
  }

  getPatternsByCategory(category: ThreatCategory): PatternRule[] {
    return this.getAllPatterns().filter((p) => p.category === category);
  }

  getPatternsBySeverity(severity: Severity): PatternRule[] {
    return this.getAllPatterns().filter((p) => p.severity === severity);
  }
}
