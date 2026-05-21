import {
  LLMMessage,
  LLMResponse,
  LLMProvider,
} from '../../../src/llm/provider-interface';

describe('LLM Provider Interface', () => {
  describe('LLMMessage', () => {
    it('should allow user role', () => {
      const message: LLMMessage = {
        role: 'user',
        content: 'test',
      };
      expect(message.role).toBe('user');
    });

    it('should allow assistant role', () => {
      const message: LLMMessage = {
        role: 'assistant',
        content: 'response',
      };
      expect(message.role).toBe('assistant');
    });
  });

  describe('LLMResponse', () => {
    it('should create response without usage', () => {
      const response: LLMResponse = {
        content: 'test content',
        model: 'test-model',
      };
      expect(response.content).toBe('test content');
      expect(response.model).toBe('test-model');
      expect(response.usage).toBeUndefined();
    });

    it('should create response with usage', () => {
      const response: LLMResponse = {
        content: 'test content',
        model: 'test-model',
        usage: {
          promptTokens: 10,
          completionTokens: 20,
          totalTokens: 30,
        },
      };
      expect(response.usage?.totalTokens).toBe(30);
    });
  });

  describe('LLMProvider interface', () => {
    it('should define required properties', () => {
      const provider: LLMProvider = {
        name: 'Test Provider',
        type: 'test',
        scan: async () => ({
          content: 'result',
          model: 'model',
        }),
        setApiKey: () => {},
      };
      expect(provider.name).toBe('Test Provider');
      expect(provider.type).toBe('test');
    });
  });
});