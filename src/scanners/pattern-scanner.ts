import { Scanner, ScanResult, ScannerType } from '../core/scanner-interface';
import { PatternLibrary, PatternRule } from '../patterns/default-patterns';

export class PatternScanner implements Scanner {
  readonly name = 'Pattern Scanner';
  readonly type = ScannerType.Pattern;

  private patternLibrary: PatternLibrary;

  constructor(customPatterns?: PatternRule[]) {
    this.patternLibrary = new PatternLibrary(customPatterns);
  }

  async scan(filePath: string, content: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const lines = content.split('\n');

    for (const pattern of this.patternLibrary.getAllPatterns()) {
      const matches = this.findMatches(content, lines, pattern);

      for (const match of matches) {
        results.push(this.createResult(filePath, pattern, match));
      }
    }

    return results;
  }

  private findMatches(
    content: string,
    lines: string[],
    pattern: PatternRule
  ): Array<{ line: number; text: string }> {
    const matches: Array<{ line: number; text: string }> = [];

    if (pattern.pattern instanceof RegExp) {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);

      let match;

      while ((match = regex.exec(content)) !== null) {
        const matchIndex = match.index;
        const lineIndex = content.substring(0, matchIndex).split('\n').length - 1;
        const lineText = lines[lineIndex] || '';

        matches.push({
          line: lineIndex + 1,
          text: lineText.trim(),
        });

        if (!regex.global) {
          break;
        }
      }
    }

    return matches;
  }

  private createResult(
    filePath: string,
    pattern: PatternRule,
    match: { line: number; text: string }
  ): ScanResult {
    return {
      id: `pattern-${pattern.id}-${Date.now()}-${Math.random()}`,
      filePath,
      lineNumber: match.line,
      severity: pattern.severity,
      category: pattern.category,
      description: pattern.description,
      evidence: match.text,
      suggestion: pattern.suggestion,
      scannerType: this.type,
    };
  }

  addCustomPattern(pattern: PatternRule): void {
    this.patternLibrary.addPattern(pattern);
  }

  getPatternCount(): number {
    return this.patternLibrary.getAllPatterns().length;
  }
}
