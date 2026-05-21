import { Formatter } from './formatter-interface';
import { FormatterType } from './formatter-interface';
import { ScanResult } from '../core/scanner-interface';
import { ScanSummary } from '../core/result';
import { Severity } from '../core/severity';

export class SARIFFormatter implements Formatter {
  readonly name = 'SARIF Formatter';

  getType(): FormatterType {
    return FormatterType.SARIF;
  }

  format(results: string): string {
    return results;
  }

  formatResults(results: ScanResult[], _summary: ScanSummary): string {
    const severityMap: Record<Severity, string> = {
      [Severity.Info]: 'note',
      [Severity.Low]: 'warning',
      [Severity.Medium]: 'warning',
      [Severity.High]: 'error',
      [Severity.Critical]: 'error',
    };

    const sarif = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'aiav',
              version: '0.0.1',
              informationUri: 'https://github.com/anthropics/aiagentantivirus',
              rules: results.map((r) => ({
                id: r.id,
                name: r.category,
                shortDescription: { text: r.description },
                fullDescription: { text: r.description },
                help: { text: r.suggestion || 'No suggestion available' },
              })),
            },
          },
          results: results.map((r) => ({
            ruleId: r.id,
            level: severityMap[r.severity],
            message: {
              text: r.description,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: r.filePath,
                  },
                  region: {
                    startLine: r.lineNumber,
                    endLine: r.lineNumber,
                  },
                },
              },
            ],
            codeFlows: r.evidence
              ? [
                  {
                    threadFlows: [
                      {
                        locations: [
                          {
                            location: {
                              physicalLocation: {
                                artifactLocation: {
                                  uri: r.filePath,
                                },
                              },
                              message: {
                                text: r.evidence,
                              },
                            },
                          },
                        ],
                      },
                    ],
                  },
                ]
              : undefined,
          })),
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }
}
