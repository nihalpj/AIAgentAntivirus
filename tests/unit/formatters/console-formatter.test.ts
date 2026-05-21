import { ConsoleFormatter } from '../../../src/formatters/console-formatter';
import { FormatterType } from '../../../src/formatters/formatter-interface';

describe('ConsoleFormatter', () => {
  let formatter: ConsoleFormatter;

  beforeEach(() => {
    formatter = new ConsoleFormatter(true);
  });

  describe('constructor', () => {
    it('should create a formatter with colors enabled by default', () => {
      const f = new ConsoleFormatter();
      expect(f.isColorsEnabled()).toBe(true);
    });

    it('should create a formatter with colors disabled when specified', () => {
      const f = new ConsoleFormatter(false);
      expect(f.isColorsEnabled()).toBe(false);
    });
  });

  describe('getType', () => {
    it('should return FormatterType.Console', () => {
      expect(formatter.getType()).toBe(FormatterType.Console);
    });
  });

  describe('format', () => {
    it('should return plain text when colors are disabled', () => {
      formatter.enableColors(false);
      const result = formatter.format('[INFO] This is a message');
      expect(result).toBe('[INFO] This is a message');
    });

    it('should apply color coding when colors are enabled', () => {
      const result = formatter.format('[CRITICAL] This is critical');
      expect(result).toContain('[CRITICAL]');
      expect(result).toContain('This is critical');
    });

    it('should colorize INFO level messages', () => {
      const result = formatter.format('[INFO] Information message');
      expect(result).toContain('[INFO]');
      expect(result).toContain('Information message');
    });

    it('should colorize LOW level messages', () => {
      const result = formatter.format('[LOW] Low severity issue');
      expect(result).toContain('[LOW]');
      expect(result).toContain('Low severity issue');
    });

    it('should colorize MEDIUM level messages', () => {
      const result = formatter.format('[MEDIUM] Medium severity issue');
      expect(result).toContain('[MEDIUM]');
      expect(result).toContain('Medium severity issue');
    });

    it('should colorize HIGH level messages', () => {
      const result = formatter.format('[HIGH] High severity issue');
      expect(result).toContain('[HIGH]');
      expect(result).toContain('High severity issue');
    });

    it('should colorize CRITICAL level messages', () => {
      const result = formatter.format('[CRITICAL] Critical severity issue');
      expect(result).toContain('[CRITICAL]');
      expect(result).toContain('Critical severity issue');
    });

    it('should colorize ERROR messages', () => {
      const result = formatter.format('[ERROR] Something went wrong');
      expect(result).toContain('[ERROR]');
      expect(result).toContain('Something went wrong');
    });

    it('should colorize SUCCESS messages', () => {
      const result = formatter.format('[SUCCESS] Operation completed');
      expect(result).toContain('[SUCCESS]');
      expect(result).toContain('Operation completed');
    });

    it('should colorize WARNING messages', () => {
      const result = formatter.format('[WARNING] Be careful');
      expect(result).toContain('[WARNING]');
      expect(result).toContain('Be careful');
    });

    it('should colorize DEBUG messages', () => {
      const result = formatter.format('[DEBUG] Debug information');
      expect(result).toContain('[DEBUG]');
      expect(result).toContain('Debug information');
    });

    it('should colorize error messages with "Error:" prefix', () => {
      const result = formatter.format('Error: Failed to process');
      expect(result).toContain('Error: Failed to process');
    });

    it('should colorize warning messages with "Warning:" prefix', () => {
      const result = formatter.format('Warning: Deprecated feature used');
      expect(result).toContain('Warning: Deprecated feature used');
    });

    it('should colorize success messages with "Success:" prefix', () => {
      const result = formatter.format('Success: All tests passed');
      expect(result).toContain('Success: All tests passed');
    });

    it('should handle empty strings', () => {
      const result = formatter.format('');
      expect(result).toBe('');
    });

    it('should handle strings without markers', () => {
      const result = formatter.format('Plain text message');
      expect(result).toBe('Plain text message');
    });

    it('should handle multiple markers in one message', () => {
      const result = formatter.format('[INFO] Starting scan... [SUCCESS] Scan complete');
      expect(result).toContain('[INFO]');
      expect(result).toContain('[SUCCESS]');
    });
  });

  describe('formatSimpleSummary', () => {
    it('should format summary with no issues', () => {
      const result = formatter.formatSimpleSummary(10, 0, 1234);
      expect(result).toContain('Files scanned:');
      expect(result).toContain('Issues found:');
      expect(result).toContain('Duration:');
      expect(result).toContain('10');
      expect(result).toContain('0');
      expect(result).toContain('1.23');
    });

    it('should format summary with issues', () => {
      const result = formatter.formatSimpleSummary(5, 3, 567);
      expect(result).toContain('Files scanned:');
      expect(result).toContain('Issues found:');
      expect(result).toContain('Duration:');
      expect(result).toContain('5');
      expect(result).toContain('3');
      expect(result).toContain('0.57');
    });

    it('should format summary header', () => {
      const result = formatter.formatSimpleSummary(0, 0, 0);
      expect(result).toContain('=== Scan Summary ===');
    });
  });

  describe('formatIssue', () => {
    it('should format an issue with critical severity', () => {
      const result = formatter.formatIssue('test.ts', 10, 'Critical', 'Critical issue detected');
      expect(result).toContain('test.ts:10');
      expect(result).toContain('[CRITICAL]');
      expect(result).toContain('Critical issue detected');
    });

    it('should format an issue with high severity', () => {
      const result = formatter.formatIssue('test.ts', 20, 'High', 'High severity issue');
      expect(result).toContain('test.ts:20');
      expect(result).toContain('[HIGH]');
      expect(result).toContain('High severity issue');
    });

    it('should format an issue with medium severity', () => {
      const result = formatter.formatIssue('test.ts', 30, 'Medium', 'Medium severity issue');
      expect(result).toContain('test.ts:30');
      expect(result).toContain('[MEDIUM]');
      expect(result).toContain('Medium severity issue');
    });

    it('should format an issue with low severity', () => {
      const result = formatter.formatIssue('test.ts', 40, 'Low', 'Low severity issue');
      expect(result).toContain('test.ts:40');
      expect(result).toContain('[LOW]');
      expect(result).toContain('Low severity issue');
    });

    it('should format an issue with info severity', () => {
      const result = formatter.formatIssue('test.ts', 50, 'Info', 'Info message');
      expect(result).toContain('test.ts:50');
      expect(result).toContain('[INFO]');
      expect(result).toContain('Info message');
    });

    it('should format an issue with unknown severity', () => {
      const result = formatter.formatIssue('test.ts', 60, 'Unknown', 'Unknown severity');
      expect(result).toContain('test.ts:60');
      expect(result).toContain('[UNKNOWN]');
      expect(result).toContain('Unknown severity');
    });

    it('should handle severity case insensitively', () => {
      const result = formatter.formatIssue('test.ts', 10, 'critical', 'Issue');
      expect(result).toContain('[CRITICAL]');
    });
  });

  describe('enableColors', () => {
    it('should enable colors', () => {
      formatter.enableColors(true);
      expect(formatter.isColorsEnabled()).toBe(true);
    });

    it('should disable colors', () => {
      formatter.enableColors(false);
      expect(formatter.isColorsEnabled()).toBe(false);
    });
  });

  describe('isColorsEnabled', () => {
    it('should return true when colors are enabled', () => {
      formatter.enableColors(true);
      expect(formatter.isColorsEnabled()).toBe(true);
    });

    it('should return false when colors are disabled', () => {
      formatter.enableColors(false);
      expect(formatter.isColorsEnabled()).toBe(false);
    });
  });
});
