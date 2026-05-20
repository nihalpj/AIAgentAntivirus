export enum Severity {
  Info = 'info',
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

export interface SeverityConfig {
  score: number;
  color: string;
  icon: string;
}

export const SEVERITY_CONFIGS: Record<Severity, SeverityConfig> = {
  [Severity.Info]: { score: 1, color: 'blue', icon: 'ℹ' },
  [Severity.Low]: { score: 2, color: 'cyan', icon: '⚠' },
  [Severity.Medium]: { score: 3, color: 'yellow', icon: '⚠' },
  [Severity.High]: { score: 4, color: 'orange', icon: '🔴' },
  [Severity.Critical]: { score: 5, color: 'red', icon: '🚨' },
};

export function getSeverityConfig(severity: Severity): SeverityConfig {
  return SEVERITY_CONFIGS[severity];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_CONFIGS[a].score - SEVERITY_CONFIGS[b].score;
}
