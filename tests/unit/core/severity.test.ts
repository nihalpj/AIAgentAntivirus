import { Severity, getSeverityConfig, compareSeverity } from '../../../src/core/severity';

describe('Severity', () => {
  describe('getSeverityConfig', () => {
    it('should return correct config for each severity', () => {
      expect(getSeverityConfig(Severity.Info)).toEqual({
        score: 1,
        color: 'blue',
        icon: 'ℹ',
      });

      expect(getSeverityConfig(Severity.Low)).toEqual({
        score: 2,
        color: 'cyan',
        icon: '⚠',
      });

      expect(getSeverityConfig(Severity.Medium)).toEqual({
        score: 3,
        color: 'yellow',
        icon: '⚠',
      });

      expect(getSeverityConfig(Severity.High)).toEqual({
        score: 4,
        color: 'orange',
        icon: '🔴',
      });

      expect(getSeverityConfig(Severity.Critical)).toEqual({
        score: 5,
        color: 'red',
        icon: '🚨',
      });
    });
  });

  describe('compareSeverity', () => {
    it('should correctly compare severities', () => {
      expect(compareSeverity(Severity.Info, Severity.Low)).toBeLessThan(0);
      expect(compareSeverity(Severity.Low, Severity.Info)).toBeGreaterThan(0);
      expect(compareSeverity(Severity.High, Severity.High)).toBe(0);
      expect(compareSeverity(Severity.Critical, Severity.Info)).toBeGreaterThan(0);
    });
  });
});
