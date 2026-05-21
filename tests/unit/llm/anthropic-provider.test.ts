import { AnthropicProvider } from '../../../src/llm/anthropic-provider';
import Anthropic from '@anthropic-ai/sdk';

// Mock the Anthropic SDK
jest.mock('@anthropic-ai/sdk');

describe('AnthropicProvider', () => {
  let provider: AnthropicProvider;

  // Create a mock client
  const mockCreate = jest.fn();

  beforeEach(() => {
    // Clear environment variables
    delete process.env.ANTHROPIC_API_KEY;

    // Mock the create method
    mockCreate.mockClear();

    (Anthropic as unknown as jest.Mock).mockImplementation(() => ({
      messages: {
        create: mockCreate,
      },
    }));

    provider = new AnthropicProvider();
  });

  describe('constructor', () => {
    it('should initialize without client when no API key', () => {
      delete process.env.ANTHROPIC_API_KEY;
      const newProvider = new AnthropicProvider();
      expect(newProvider['client']).toBeNull();
    });

    it('should have correct name and type', () => {
      expect(provider.name).toBe('Anthropic');
      expect(provider.type).toBe('anthropic');
    });
  });

  describe('setApiKey', () => {
    it('should create new client with provided API key', () => {
      provider.setApiKey('test-api-key');
      expect(Anthropic).toHaveBeenCalledWith({ apiKey: 'test-api-key' });
      expect(provider['client']).not.toBeNull();
    });
  });

  describe('scan', () => {
    it('should throw error when client is not configured', async () => {
      await expect(
        provider.scan('/test/file.js', 'const x = 1;')
      ).rejects.toThrow('Anthropic API key not configured');
    });

    it('should return successful scan result', async () => {
      provider.setApiKey('test-key');

      const mockResponse = {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              issues: [
                {
                  severity: 'high',
                  category: 'unsafe-execution',
                  description: 'Dangerous eval usage',
                  lineNumber: 1,
                  evidence: 'eval(userInput)',
                  suggestion: 'Use safer alternatives',
                },
              ],
              summary: 'One security issue found',
            }),
          },
        ],
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      mockCreate.mockResolvedValue(mockResponse);

      const result = await provider.scan('/test/file.js', 'eval(userInput);');

      expect(result.content).toContain('issues');
      expect(result.model).toBe('claude-3-haiku-20240307');
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
        content: [{ type: 'text' as const, text: '{}' }],
        usage: { input_tokens: 100, output_tokens: 50 },
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
      ).rejects.toThrow('Anthropic scan failed');
    });

    it('should handle non-text content type', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        content: [{ type: 'image' as const, source: { data: '' } }],
        usage: { input_tokens: 100, output_tokens: 50 },
      });

      const result = await provider.scan('/test/file.js', 'const x = 1;');

      expect(result.content).toBe('');
    });

    it('should include file path in prompt', async () => {
      provider.setApiKey('test-key');

      mockCreate.mockResolvedValue({
        content: [{ type: 'text' as const, text: '{}' }],
        usage: { input_tokens: 100, output_tokens: 50 },
      });

      await provider.scan('/path/to/test.js', 'const x = 1;');

      const callArgs = mockCreate.mock.calls[0];
      const prompt = callArgs[0].messages[0].content;

      expect(prompt).toContain('/path/to/test.js');
    });
  });
});