export interface LLMMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

export interface LLMProvider {
  readonly name: string;
  readonly type: string;
  scan(filePath: string, content: string): Promise<LLMResponse>;
  setApiKey(apiKey: string): void;
}
