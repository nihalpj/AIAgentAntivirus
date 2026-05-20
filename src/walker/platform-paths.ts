import * as os from 'os';
import * as path from 'path';

export type Platform =
  | 'claude'
  | 'openai'
  | 'google'
  | 'cursor'
  | 'vscode'
  | 'all';

export interface PlatformPath {
  platform: Platform;
  paths: string[];
}

const LINUX_PLATFORM_PATHS: PlatformPath[] = [
  { platform: 'claude', paths: ['~/.claude', '~/.config/Claude', '~/.config/anthropic'] },
  { platform: 'openai', paths: ['~/.config/openai', '~/.openai'] },
  { platform: 'google', paths: ['~/.config/google', '~/.config/gemini', '~/.local/share/google'] },
  { platform: 'cursor', paths: ['~/.cursor/extensions'] },
  { platform: 'vscode', paths: ['~/.vscode/extensions', '~/.config/Code/User'] }
];

const WINDOWS_PLATFORM_PATHS: PlatformPath[] = [
  {
    platform: 'claude',
    paths: [
      '%USERPROFILE%\\AppData\\Roaming\\Claude',
      '%USERPROFILE%\\AppData\\Roaming\\anthropic',
      '%USERPROFILE%\\.claude'
    ]
  },
  {
    platform: 'openai',
    paths: [
      '%USERPROFILE%\\AppData\\Roaming\\openai',
      '%USERPROFILE%\\.openai'
    ]
  },
  {
    platform: 'google',
    paths: [
      '%USERPROFILE%\\AppData\\Roaming\\google',
      '%USERPROFILE%\\AppData\\Local\\google'
    ]
  },
  {
    platform: 'cursor',
    paths: ['%USERPROFILE%\\.cursor\\extensions']
  },
  {
    platform: 'vscode',
    paths: [
      '%USERPROFILE%\\.vscode\\extensions',
      '%USERPROFILE%\\AppData\\Roaming\\Code\\User'
    ]
  }
];

const DARWIN_PLATFORM_PATHS: PlatformPath[] = [
  { platform: 'claude', paths: ['~/Library/Application Support/Claude'] },
  { platform: 'openai', paths: ['~/Library/Application Support/OpenAI'] },
  { platform: 'google', paths: ['~/Library/Application Support/Google'] },
  { platform: 'cursor', paths: ['~/.cursor/extensions'] },
  { platform: 'vscode', paths: ['~/.vscode/extensions', '~/Library/Application Support/Code/User'] }
];

export class PlatformPathDetector {
  private platform: NodeJS.Platform;
  private homeDir: string;

  constructor() {
    this.platform = os.platform();
    this.homeDir = os.homedir();
  }

  getPlatformPaths(platformFilter: Platform = 'all'): string[] {
    const allPaths = this.getAllPlatformPaths();

    if (platformFilter === 'all') {
      return this.expandPaths(allPaths);
    }

    const filtered = allPaths.filter(p => p.platform === platformFilter);
    return this.expandPaths(filtered);
  }

  private getAllPlatformPaths(): PlatformPath[] {
    switch (this.platform) {
      case 'win32':
        return WINDOWS_PLATFORM_PATHS;
      case 'darwin':
        return DARWIN_PLATFORM_PATHS;
      default:
        return LINUX_PLATFORM_PATHS;
    }
  }

  private expandPaths(platformPaths: PlatformPath[]): string[] {
    return platformPaths.flatMap(pp =>
      pp.paths.map(p => this.expandPath(p))
    );
  }

  private expandPath(rawPath: string): string {
    const expanded = rawPath
      .replace(/^~/, this.homeDir)
      .replace(/%USERPROFILE%/gi, this.homeDir)
      .replace(/%HOME%/gi, this.homeDir);

    return path.normalize(expanded);
  }

  async detectExistingPaths(platformFilter: Platform = 'all'): Promise<string[]> {
    const fs = await import('fs-extra');
    const paths = this.getPlatformPaths(platformFilter);
    const existing: string[] = [];

    for (const p of paths) {
      if (await fs.pathExists(p)) {
        existing.push(p);
      }
    }

    return existing;
  }
}