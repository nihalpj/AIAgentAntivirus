import { LLMScanner } from '../../../src/scanners/llm-scanner';
import { Severity } from '../../../src/core/severity';
import { ThreatCategory, ScannerType } from '../../../src/core/scanner-interface';
import { AnthropicProvider } from '../../../src/llm/anthropic-provider';
import { OpenAIProvider } from '../../../src/llm/openai-provider';

// Mock the providers
jest.mock('../../../src/llm/anthropic-provider');
jest.mock('../../../src/llm/openai-provider');

describe('LLMScanner', () => {
  let scanner: LLMScanner;
  let mockProvider: jest.Mocked<any>;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Create a mock provider
    mockProvider = {
      name: 'Mock Provider',
      type: 'mock',
      setApiKey: jest.fn(),
      scan: jest.fn(),
    };

    (AnthropicProvider as jest.Mock).mockImplementation(() => mockProvider);
    (OpenAIProvider as jest.Mock).mockImplementation(() => mockProvider);
  });

  describe('constructor', () => {
    it('should create scanner with Anthropic provider by default', () => {
      scanner = new LLMScanner();
      expect(AnthropicProvider).toHaveBeenCalled();
    });

    it('should create scanner with Anthropic provider when specified', () => {
      scanner = new LLMScanner('anthropic');
      expect(AnthropicProvider).toHaveBeenCalled();
      expect(OpenAIProvider).not.toHaveBeenCalled();
    });

    it('should create scanner with OpenAI provider when specified', () => {
      scanner = new LLMScanner('openai');
      expect(OpenAIProvider).toHaveBeenCalled();
      expect(AnthropicProvider).not.toHaveBeenCalled();
    });

    it('should have correct name and type', () => {
      scanner = new LLMScanner();
      expect(scanner.name).toBe('LLM Scanner');
      expect(scanner.type).toBe(ScannerType.LLM);
    });
  });

  describe('scan', () => {
    it('should parse and return valid issues', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [
            {
              severity: 'high',
              category: 'prompt-injection',
              description: 'Potential prompt injection',
              lineNumber: 5,
              evidence: 'ignore all previous instructions',
              suggestion: 'Validate user input',
            },
          ],
          summary: 'One issue found',
        }),
        model: 'test-model',
        usage: { promptTokens: 10, completionTokens: 20, totalTokens: 30 },
      });

      scanner = new LLMScanner('anthropic');
      const results = await scanner.scan('/test/file.js', 'test content');

      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe(Severity.High);
      expect(results[0].category).toBe(ThreatCategory.PromptInjection);
      expect(results[0].description).toBe('Potential prompt injection');
      expect(results[0].lineNumber).toBe(5);
      expect(results[0].evidence).toBe('ignore all previous instructions');
      expect(results[0].suggestion).toBe('Validate user input');
      expect(results[0].scannerType).toBe(ScannerType.LLM);
    });

    it('should parse multiple issues', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [
            {
              severity: 'critical',
              category: 'hardcoded-secret',
              description: 'API key hardcoded',
              lineNumber: 1,
              evidence: 'sk-123456',
              suggestion: 'Use env vars',
            },
            {
              severity: 'medium',
              category: 'unsafe-execution',
              description: 'eval usage',
              lineNumber: 10,
              evidence: 'eval(userInput)',
              suggestion: 'Use JSON.parse or safer alternatives',
            },
          ],
          summary: 'Two issues found',
        }),
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results).toHaveLength(2);
      expect(results[0].severity).toBe(Severity.Critical);
      expect(results[0].category).toBe(ThreatCategory.HardcodedSecret);
      expect(results[1].severity).toBe(Severity.Medium);
      expect(results[1].category).toBe(ThreatCategory.UnsafeExecution);
    });

    it('should handle empty issues array', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [],
          summary: 'No security issues found',
        }),
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'safe content');

      expect(results).toHaveLength(0);
    });

    it('should handle malformed JSON response', async () => {
      mockProvider.scan.mockResolvedValue({
        content: 'Not valid JSON at all',
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results).toHaveLength(0);
    });

    it('should handle provider errors gracefully', async () => {
      mockProvider.scan.mockRejectedValue(new Error('API key not configured'));

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results).toHaveLength(0);
    });

    it('should parse all severity levels correctly', async () => {
      const severities = ['critical', 'high', 'medium', 'low', 'info'];

      for (const severity of severities) {
        mockProvider.scan.mockResolvedValue({
          content: JSON.stringify({
            issues: [
              {
                severity,
                category: 'other',
                description: 'Test',
                lineNumber: 1,
              },
            ],
            summary: 'Test',
          }),
          model: 'test-model',
        });

        scanner = new LLMScanner();
        const results = await scanner.scan('/test/file.js', 'content');

        expect(results[0].severity).toBeDefined();
        mockProvider.scan.mockClear();
      }
    });

    it('should parse all threat categories correctly', async () => {
      const categories = [
        'prompt-injection',
        'hardcoded-secret',
        'unsafe-execution',
        'malicious-command',
        'obfuscation',
        'data-exfiltration',
        'social-engineering',
      ];

      for (const category of categories) {
        mockProvider.scan.mockResolvedValue({
          content: JSON.stringify({
            issues: [
              {
                severity: 'medium',
                category,
                description: 'Test',
                lineNumber: 1,
              },
            ],
            summary: 'Test',
          }),
          model: 'test-model',
        });

        scanner = new LLMScanner();
        const results = await scanner.scan('/test/file.js', 'content');

        expect(results[0].category).toBeDefined();
        mockProvider.scan.mockClear();
      }
    });

    it('should map unknown category to Other', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [
            {
              severity: 'medium',
              category: 'unknown-category',
              description: 'Test',
              lineNumber: 1,
            },
          ],
          summary: 'Test',
        }),
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results[0].category).toBe(ThreatCategory.Other);
    });

    it('should map unknown severity to Medium', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [
            {
              severity: 'unknown',
              category: 'other',
              description: 'Test',
              lineNumber: 1,
            },
          ],
          summary: 'Test',
        }),
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results[0].severity).toBe(Severity.Medium);
    });

    it('should handle missing optional fields', async () => {
      mockProvider.scan.mockResolvedValue({
        content: JSON.stringify({
          issues: [
            {
              severity: 'low',
              category: 'other',
              description: 'Minimal issue',
            },
          ],
          summary: 'Test',
        }),
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results).toHaveLength(1);
      expect(results[0].lineNumber).toBe(1);
      expect(results[0].evidence).toBeUndefined();
      expect(results[0].suggestion).toBeUndefined();
    });

    it('should handle JSON with markdown formatting', async () => {
      mockProvider.scan.mockResolvedValue({
        content: `Here's the analysis:

\`\`\`json
{
  "issues": [
    {
      "severity": "high",
      "category": "prompt-injection",
      "description": "Test issue",
      "lineNumber": 1
    }
  ],
  "summary": "One issue"
}
\`\`\`

Additional notes...`,
        model: 'test-model',
      });

      scanner = new LLMScanner();
      const results = await scanner.scan('/test/file.js', 'content');

      expect(results).toHaveLength(1);
      expect(results[0].description).toBe('Test issue');
    });
  });

  describe('setApiKey', () => {
    it('should call setApiKey on provider', () => {
      scanner = new LLMScanner();
      scanner.setApiKey('new-api-key');

      expect(mockProvider.setApiKey).toHaveBeenCalledWith('new-api-key');
    });
  });
});
