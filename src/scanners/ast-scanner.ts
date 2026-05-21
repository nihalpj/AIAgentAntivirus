import { Scanner, ScanResult, ScannerType, ThreatCategory } from '../core/scanner-interface';
import { Severity } from '../core/severity';

interface ASTPattern {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: Severity;
  check: (ast: any, filePath: string) => ScanResult[];
}

export class ASTScanner implements Scanner {
  readonly name = 'AST Scanner';
  readonly type = ScannerType.AST;

  private patterns: ASTPattern[] = [
    {
      id: 'ast-eval-usage',
      name: 'eval() function call',
      category: ThreatCategory.UnsafeExecution,
      severity: Severity.High,
      check: (ast, filePath) => this.checkEvalUsage(ast, filePath),
    },
    {
      id: 'ast-dangerous-import',
      name: 'Dynamic import with variable',
      category: ThreatCategory.UnsafeExecution,
      severity: Severity.High,
      check: (ast, filePath) => this.checkDynamicImport(ast, filePath),
    },
    {
      id: 'ast-prototype-pollution',
      name: 'Prototype pollution risk',
      category: ThreatCategory.MaliciousCommand,
      severity: Severity.Critical,
      check: (ast, filePath) => this.checkPrototypePollution(ast, filePath),
    },
  ];

  async scan(filePath: string, content: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const ext = filePath.split('.').pop()?.toLowerCase();

    try {
      const ast = await this.parseAST(content, ext);
      if (!ast) return results;

      for (const pattern of this.patterns) {
        const patternResults = pattern.check(ast, filePath);
        results.push(...patternResults);
      }
    } catch (error) {
      console.warn(`AST parsing failed for ${filePath}: ${error}`);
    }

    return results;
  }

  private async parseAST(content: string, ext?: string): Promise<any> {
    if (!ext || !['js', 'ts', 'jsx', 'tsx', 'py'].includes(ext)) {
      return null;
    }

    try {
      const Parser = await this.getParser(ext);
      if (!Parser) return null;
      const parser = new Parser();
      return parser.parse(content);
    } catch {
      return null;
    }
  }

  private async getParser(ext: string): Promise<any> {
    switch (ext) {
      case 'js':
      case 'jsx':
        return (await import('tree-sitter-javascript')).default;
      case 'ts':
      case 'tsx':
        return (await import('tree-sitter-typescript')).default;
      case 'py':
        return (await import('tree-sitter-python')).default;
      default:
        return null;
    }
  }

  private checkEvalUsage(ast: any, filePath: string): ScanResult[] {
    const results: ScanResult[] = [];
    const findEval = (node: any) => {
      if (!node) return;

      if (node.type === 'call_expression') {
        const func = node.childForFieldName('function');
        if (func && func.text === 'eval') {
          results.push({
            id: `ast-eval-${Date.now()}`,
            filePath,
            lineNumber: node.startPosition.row + 1,
            severity: Severity.High,
            category: ThreatCategory.UnsafeExecution,
            description: 'Use of eval() detected',
            evidence: node.text,
            suggestion: 'Avoid eval() - use safer alternatives',
            scannerType: this.type,
          });
        }
      }

      if (node.namedChildren) {
        for (const child of node.namedChildren) {
          findEval(child);
        }
      }
    };

    findEval(ast.rootNode);
    return results;
  }

  private checkDynamicImport(ast: any, filePath: string): ScanResult[] {
    const results: ScanResult[] = [];
    const findDynamicImport = (node: any) => {
      if (!node) return;

      if (node.type === 'import_statement' || node.type === 'call_expression') {
        const text = node.text;
        if (text.includes('import(') && !text.includes('"') && !text.includes("'")) {
          results.push({
            id: `ast-dynamic-import-${Date.now()}`,
            filePath,
            lineNumber: node.startPosition.row + 1,
            severity: Severity.High,
            category: ThreatCategory.UnsafeExecution,
            description: 'Dynamic import with variable detected',
            evidence: text,
            suggestion: 'Validate module paths before dynamic imports',
            scannerType: this.type,
          });
        }
      }

      if (node.namedChildren) {
        for (const child of node.namedChildren) {
          findDynamicImport(child);
        }
      }
    };

    findDynamicImport(ast.rootNode);
    return results;
  }

  private checkPrototypePollution(ast: any, filePath: string): ScanResult[] {
    const results: ScanResult[] = [];
    const findPrototypeAccess = (node: any) => {
      if (!node) return;

      if (node.type === 'member_expression' || node.type === 'subscript_expression') {
        const text = node.text;
        if (text.includes('__proto__') || text.includes('constructor')) {
          results.push({
            id: `ast-proto-${Date.now()}`,
            filePath,
            lineNumber: node.startPosition.row + 1,
            severity: Severity.Critical,
            category: ThreatCategory.MaliciousCommand,
            description: 'Prototype pollution risk detected',
            evidence: text,
            suggestion: 'Validate object keys and avoid direct prototype access',
            scannerType: this.type,
          });
        }
      }

      if (node.namedChildren) {
        for (const child of node.namedChildren) {
          findPrototypeAccess(child);
        }
      }
    };

    findPrototypeAccess(ast.rootNode);
    return results;
  }
}
