import cron, { ScheduledTask } from 'node-cron';

export interface ScheduleOptions {
  cronExpression: string;
  timezone?: string;
}

export class Scheduler {
  private tasks: Map<string, ScheduledTask> = new Map();

  schedule(name: string, cronExpression: string, callback: () => void, timezone?: string): void {
    const task = cron.schedule(cronExpression, () => callback(), {
      name,
      timezone: timezone || 'UTC'
    });

    this.tasks.set(name, task);
  }

  stop(name: string): void {
    const task = this.tasks.get(name);
    if (task) {
      task.stop();
      this.tasks.delete(name);
    }
  }

  stopAll(): void {
    for (const task of this.tasks.values()) {
      task.stop();
    }
    this.tasks.clear();
  }

  hasTask(name: string): boolean {
    return this.tasks.has(name);
  }

  getTaskCount(): number {
    return this.tasks.size;
  }
}