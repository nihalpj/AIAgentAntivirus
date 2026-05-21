export interface AlertConfig {
  enabled: boolean;
  webhookUrl?: string;
  webhookMethod?: 'POST' | 'PUT';
  webhookHeaders?: Record<string, string>;
}

export interface Alert {
  timestamp: Date;
  filePath: string;
  severity: string;
  category: string;
  description: string;
}

export class AlertSystem {
  private config: AlertConfig;

  constructor(config: AlertConfig = { enabled: false }) {
    this.config = config;
  }

  async sendAlert(alert: Alert): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    if (this.config.webhookUrl) {
      await this.sendWebhook(alert);
    }

    this.logAlert(alert);
  }

  private async sendWebhook(alert: Alert): Promise<void> {
    try {
      await fetch(this.config.webhookUrl!, {
        method: this.config.webhookMethod || 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.config.webhookHeaders,
        },
        body: JSON.stringify(alert),
      });
    } catch (error) {
      console.error(`Failed to send webhook: ${error}`);
    }
  }

  private logAlert(alert: Alert): void {
    console.log(
      `[ALERT] ${alert.timestamp.toISOString()} - ${alert.severity.toUpperCase()} - ${alert.filePath}`
    );
    console.log(`  ${alert.category}: ${alert.description}`);
  }

  updateConfig(config: Partial<AlertConfig>): void {
    this.config = { ...this.config, ...config };
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }
}
