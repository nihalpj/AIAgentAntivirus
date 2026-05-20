export interface Formatter {
  format(results: string): string;
}

export enum FormatterType {
  Console = 'console',
  JSON = 'json',
  Markdown = 'markdown',
  HTML = 'html',
}