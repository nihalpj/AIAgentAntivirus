import { AlertSystem, Alert, AlertConfig } from '../../../src/watcher/alert-system';

describe('AlertSystem', () => {
  let alertSystem: AlertSystem;
  const originalConsoleLog = console.log;
  const originalConsoleError = console.error;

  beforeEach(() => {
    alertSystem = new AlertSystem({ enabled: false });
    console.log = jest.fn();
    console.error = jest.fn();
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  describe('constructor', () => {
    it('should initialize with default config', () => {
      const system = new AlertSystem();
      expect(system.isEnabled()).toBe(false);
    });

    it('should initialize with custom config', () => {
      const config: AlertConfig = {
        enabled: true,
        webhookUrl: 'https://example.com/webhook',
        webhookMethod: 'PUT',
        webhookHeaders: { 'X-Custom': 'value' }
      };
      const system = new AlertSystem(config);
      expect(system.isEnabled()).toBe(true);
    });
  });

  describe('sendAlert', () => {
    it('should not send alert when disabled', async () => {
      const alert: Alert = {
        timestamp: new Date(),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);
      expect(console.log).not.toHaveBeenCalled();
    });

    it('should log alert when enabled', async () => {
      alertSystem.updateConfig({ enabled: true });

      const alert: Alert = {
        timestamp: new Date('2024-01-01T12:00:00Z'),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);

      expect(console.log).toHaveBeenCalledWith(
        '[ALERT] 2024-01-01T12:00:00.000Z - HIGH - /test/file.js'
      );
      expect(console.log).toHaveBeenCalledWith('  test: Test alert');
    });

    it('should send webhook when configured', async () => {
      global.fetch = jest.fn(() =>
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ success: true })
        } as Response)
      ) as jest.Mock;

      alertSystem.updateConfig({
        enabled: true,
        webhookUrl: 'https://example.com/webhook',
        webhookMethod: 'POST'
      });

      const alert: Alert = {
        timestamp: new Date(),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://example.com/webhook',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          }),
          body: expect.stringContaining('test')
        })
      );
    });

    it('should use custom headers in webhook', async () => {
      global.fetch = jest.fn(() =>
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ success: true })
        } as Response)
      ) as jest.Mock;

      alertSystem.updateConfig({
        enabled: true,
        webhookUrl: 'https://example.com/webhook',
        webhookHeaders: {
          'Authorization': 'Bearer token123',
          'X-Custom': 'custom-value'
        }
      });

      const alert: Alert = {
        timestamp: new Date(),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-Custom': 'custom-value'
          })
        })
      );
    });

    it('should handle webhook errors gracefully', async () => {
      global.fetch = jest.fn(() =>
        Promise.reject(new Error('Network error'))
      ) as jest.Mock;

      alertSystem.updateConfig({
        enabled: true,
        webhookUrl: 'https://example.com/webhook'
      });

      const alert: Alert = {
        timestamp: new Date(),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to send webhook')
      );
    });

    it('should use PUT method when configured', async () => {
      global.fetch = jest.fn(() =>
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ success: true })
        } as Response)
      ) as jest.Mock;

      alertSystem.updateConfig({
        enabled: true,
        webhookUrl: 'https://example.com/webhook',
        webhookMethod: 'PUT'
      });

      const alert: Alert = {
        timestamp: new Date(),
        filePath: '/test/file.js',
        severity: 'high',
        category: 'test',
        description: 'Test alert'
      };

      await alertSystem.sendAlert(alert);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          method: 'PUT'
        })
      );
    });
  });

  describe('updateConfig', () => {
    it('should merge new config with existing', () => {
      alertSystem.updateConfig({ enabled: true });
      expect(alertSystem.isEnabled()).toBe(true);

      alertSystem.updateConfig({ webhookUrl: 'https://example.com/webhook' });
      expect(alertSystem.isEnabled()).toBe(true);
    });

    it('should override existing config values', () => {
      alertSystem.updateConfig({ enabled: true });
      expect(alertSystem.isEnabled()).toBe(true);

      alertSystem.updateConfig({ enabled: false });
      expect(alertSystem.isEnabled()).toBe(false);
    });
  });

  describe('isEnabled', () => {
    it('should return false by default', () => {
      const system = new AlertSystem();
      expect(system.isEnabled()).toBe(false);
    });

    it('should return true when enabled', () => {
      const system = new AlertSystem({ enabled: true });
      expect(system.isEnabled()).toBe(true);
    });
  });
});