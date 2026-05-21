import { Scanner, ScanResult, ScannerType, ThreatCategory } from '../core/scanner-interface';
import { Severity } from '../core/severity';
import { LLMProvider } from '../llm/provider-interface';
import { AnthropicProvider } from '../llm/anthropic-provider';
import { OpenAIProvider } from '../llm/openai-provider';

interface LLMIssue {
  severity: string;
  category: string;
  description: string;
  lineNumber: number;
  evidence?: string;
  suggestion?: string;
}

interface LLMScanResponse {
  issues: LLMIssue[];
  summary: string;
}

export class LLMScanner implements Scanner {
  readonly name = 'LLM Scanner';
  readonly type = ScannerType.LLM;

  private provider: LLMProvider;

  constructor(providerType: 'anthropic' | 'openai' = 'anthropic') {
    switch (providerType) {
      case 'anthropic':
        this.provider = new AnthropicProvider();
        break;
      case 'openai':
        this.provider = new OpenAIProvider();
        break;
    }
  }

  async scan(filePath: string, content: string): Promise<ScanResult[]> {
    try {
      const response = await this.provider.scan(filePath, content);
      return this.parseResponse(filePath, response.content);
    } catch (error) {
      console.warn(`LLM scan failed for ${filePath}: ${error}`);
      return [];
    }
  }

  private parseResponse(filePath: string, content: string): ScanResult[] {
    const results: ScanResult[] = [];

    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return results;
      }

      const parsed: LLMScanResponse = JSON.parse(jsonMatch[0]);

      for (const issue of parsed.issues) {
        results.push({
          id: `llm-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          filePath,
          lineNumber: issue.lineNumber || 1,
          severity: this.parseSeverity(issue.severity),
          category: this.parseCategory(issue.category),
          description: issue.description,
          evidence: issue.evidence,
          suggestion: issue.suggestion,
          scannerType: this.type,
        });
      }
    } catch {
      // Failed to parse LLM response
    }

    return results;
  }

  private parseSeverity(severity: string): Severity {
    const severityMap: Record<string, Severity> = {
      critical: Severity.Critical,
      high: Severity.High,
      medium: Severity.Medium,
      low: Severity.Low,
      info: Severity.Info,
    };
    return severityMap[severity.toLowerCase()] || Severity.Medium;
  }

  private parseCategory(category: string): ThreatCategory {
    const categoryMap: Record<string, ThreatCategory> = {
      'prompt-injection': ThreatCategory.PromptInjection,
      'hardcoded-secret': ThreatCategory.HardcodedSecret,
      'unsafe-execution': ThreatCategory.UnsafeExecution,
      'malicious-command': ThreatCategory.MaliciousCommand,
      obfuscation: ThreatCategory.Obfuscation,
      'data-exfiltration': ThreatCategory.DataExfiltration,
      'social-engineering': ThreatCategory.SocialEngineering,
    };
    return categoryMap[category.toLowerCase()] || ThreatCategory.Other;
  }

  setApiKey(apiKey: string): void {
    this.provider.setApiKey(apiKey);
  }
}