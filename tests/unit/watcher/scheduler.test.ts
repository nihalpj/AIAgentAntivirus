import { Scheduler } from '../../../src/watcher/scheduler';

describe('Scheduler', () => {
  let scheduler: Scheduler;

  beforeEach(() => {
    jest.useFakeTimers();
    scheduler = new Scheduler();
  });

  afterEach(() => {
    jest.useRealTimers();
    scheduler.stopAll();
  });

  describe('schedule', () => {
    it('should schedule a task with cron expression', () => {
      const callback = jest.fn();

      // Schedule task
      scheduler.schedule('test-task', '* * * * * *', () => callback());

      // Note: With fake timers, we can't easily test node-cron's actual execution
      // because node-cron uses setInterval internally. We'll test the API instead.
      expect(scheduler.hasTask('test-task')).toBe(true);
      expect(scheduler.getTaskCount()).toBe(1);
    });

    it('should schedule multiple tasks', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      scheduler.schedule('task1', '* * * * * *', () => callback1());
      scheduler.schedule('task2', '* * * * * *', () => callback2());

      expect(scheduler.hasTask('task1')).toBe(true);
      expect(scheduler.hasTask('task2')).toBe(true);
      expect(scheduler.getTaskCount()).toBe(2);
    });

    it('should replace existing task with same name', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      scheduler.schedule('task1', '* * * * * *', () => callback1());
      expect(scheduler.hasTask('task1')).toBe(true);

      scheduler.schedule('task1', '* * * * * *', () => callback2());
      expect(scheduler.hasTask('task1')).toBe(true);
      expect(scheduler.getTaskCount()).toBe(1);
    });

    it('should use default UTC timezone if not specified', () => {
      scheduler.schedule('utc-task', '* * * * * *', jest.fn());

      expect(scheduler.hasTask('utc-task')).toBe(true);
    });

    it('should accept custom timezone', () => {
      scheduler.schedule('tz-task', '* * * * * *', jest.fn(), 'America/New_York');

      expect(scheduler.hasTask('tz-task')).toBe(true);
    });
  });

  describe('stop', () => {
    it('should stop a specific task', () => {
      scheduler.schedule('stop-task', '* * * * * *', jest.fn());

      expect(scheduler.hasTask('stop-task')).toBe(true);

      scheduler.stop('stop-task');

      expect(scheduler.hasTask('stop-task')).toBe(false);
    });

    it('should not error when stopping non-existent task', () => {
      expect(() => {
        scheduler.stop('non-existent');
      }).not.toThrow();
    });
  });

  describe('stopAll', () => {
    it('should stop all tasks', () => {
      scheduler.schedule('task1', '* * * * * *', jest.fn());
      scheduler.schedule('task2', '* * * * * *', jest.fn());
      scheduler.schedule('task3', '* * * * * *', jest.fn());

      expect(scheduler.getTaskCount()).toBe(3);

      scheduler.stopAll();

      expect(scheduler.getTaskCount()).toBe(0);
      expect(scheduler.hasTask('task1')).toBe(false);
      expect(scheduler.hasTask('task2')).toBe(false);
      expect(scheduler.hasTask('task3')).toBe(false);
    });

    it('should handle empty scheduler', () => {
      expect(() => {
        scheduler.stopAll();
      }).not.toThrow();

      expect(scheduler.getTaskCount()).toBe(0);
    });
  });

  describe('hasTask', () => {
    it('should return true for existing task', () => {
      scheduler.schedule('existing-task', '* * * * * *', jest.fn());

      expect(scheduler.hasTask('existing-task')).toBe(true);
    });

    it('should return false for non-existent task', () => {
      expect(scheduler.hasTask('non-existent-task')).toBe(false);
    });
  });

  describe('getTaskCount', () => {
    it('should return 0 for empty scheduler', () => {
      expect(scheduler.getTaskCount()).toBe(0);
    });

    it('should return correct count after adding tasks', () => {
      scheduler.schedule('task1', '* * * * * *', jest.fn());
      scheduler.schedule('task2', '* * * * * *', jest.fn());
      scheduler.schedule('task3', '* * * * * *', jest.fn());

      expect(scheduler.getTaskCount()).toBe(3);
    });

    it('should update count after removing tasks', () => {
      scheduler.schedule('task1', '* * * * * *', jest.fn());
      scheduler.schedule('task2', '* * * * * *', jest.fn());

      expect(scheduler.getTaskCount()).toBe(2);

      scheduler.stop('task1');

      expect(scheduler.getTaskCount()).toBe(1);
    });
  });
});