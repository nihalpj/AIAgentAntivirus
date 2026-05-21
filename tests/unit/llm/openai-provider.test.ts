import { OpenAIProvider } from '../../../src/llm/openai-provider';
import OpenAI from 'openai';

// Mock the OpenAI SDK
jest.mock('openai');

describe('OpenAIProvider', () => {
  let provider: OpenAIProvider;

  // Create a mock client
  const mockCreate = jest.fn();

  beforeEach(() => {
    // Clear environment variables
    delete process.env.OPENAI_API_KEY;

    // Mock the create method
    mockCreate.mockClear();

    (OpenAI as unknown as jest.Mock).mockImplementation(() => ({
      chat: {
        completions: {
          create: mockCreate,
        },
      },
    }));

    provider = new OpenAIProvider();
  });

  describe('constructor', () => {
    it('should initialize without client when no API key', () => {
      delete process.env.OPENAI_API_KEY;
      const newProvider = new OpenAIProvider();
      expect(newProvider['client']).toBeNull();
    });

    it('should have correct name and type', () => {
      expect(provider.name).toBe('OpenAI');
      expect(provider.type).toBe('openai');
    });
  });

  describe('setApiKey', () => {
    it('should create new client with provided API key', () => {
      provider.setApiKey('test-api-key');
      expect(OpenAI).toHaveBeenCalledWith({ apiKey: 'test-api-key' });
      expect(provider['client']).not.toBeNull();
    });
  });

  describe('scan', () => {
    it('should throw error when client is not configured', async () => {
      await expect(
        provider.scan('/test/file.js', 'const x = 1;')
      ).rejects.toThrow('OpenAI API key not configured');
    });

    it('should return successful scan result', async () => {
      provider.setApiKey('test-key');

      const mockResponse = {
        choices: [
          {
            message: {
              content: JSON.stringify({
                issues: [
                  {
                    severity: 'critical',
                    category: 'hardcoded-secret',
                    description: 'Hardcoded API key found',
                    lineNumber: 1,
                    evidence: 'const apiKey = "sk-12345"',
                    suggestion: 'Use environment variables',
                  },
                ],
                summary: 'Critical security issue found',
              }),
            },
          },
        ],
        usage: {
          prompt_tokens: 100,
          completion_tokens: 50,
          total_tokens: 150,
        },
      };

      mockCreate.mockResolvedValue(mockResponse);

      const result = await provider.scan('/test/file.js', 'eval(userInput);');

      expect(result.content).toContain('issues');
      expect(result.model).toBe('gpt-4o-mini');
      expect(result.usage).toEqual({
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      });
    });

    it('should handle content exceeding 10000 chars', async () => {
      provider.setApiKey('test-key');

      const longContent = 'a'.repeat(20000);

      mockCreate.mockResolvedValue({
        choices: [{ message: { content: '{}' } }],
        usage: { prompt_tokens: 100, completion_tokens: 50 },
      });

      await provider.scan('/test/file.js', longContent);

      const callArgs = mockCreate.mock.calls[0];
      const prompt = callArgs[0].messages[0].content;

      expect(prompt.length).toBeLessThan(20000);
      expect(prompt).toContain(longContent.substring(0, 10000));
    });

    it('should handle API errors', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockRejectedValue(new Error('API Error: Rate limit exceeded'));

      await expect(
        provider.scan('/test/file.js', 'const x = 1;')
      ).rejects.toThrow('OpenAI scan failed');
    });

    it('should handle missing usage data', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        choices: [{ message: { content: '{}' } }],
      });

      const result = await provider.scan('/test/file.js', 'const x = 1;');

      expect(result.usage).toEqual({
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
      });
    });

    it('should handle empty content from API', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        choices: [],
      });

      const result = await provider.scan('/test/file.js', 'const x = 1;');

      expect(result.content).toBe('');
    });

    it('should handle missing message content', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        choices: [{}],
        usage: { prompt_tokens: 100, completion_tokens: 50 },
      });

      const result = await provider.scan('/test/file.js', 'const x = 1;');

      expect(result.content).toBe('');
    });

    it('should include file path in prompt', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        choices: [{ message: { content: '{}' } }],
        usage: { prompt_tokens: 100, completion_tokens: 50 },
      });

      await provider.scan('/path/to/test.js', 'const x = 1;');

      const callArgs = mockCreate.mock.calls[0];
      const prompt = callArgs[0].messages[0].content;

      expect(prompt).toContain('/path/to/test.js');
    });
  });
});