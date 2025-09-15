import ivm from 'isolated-vm';
import { EventEmitter } from 'events';
import { Logger } from '../logger';
import { MetricsCollector } from '../metrics';

export interface PluginMetadata {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  permissions: string[];
  dependencies?: string[];
  hooks: string[];
  maxMemory: number;
  maxCpuTime: number;
}

export interface PluginContext {
  tenant_id: string;
  user_id: string;
  email?: any;
  metadata: PluginMetadata;
}

export interface PluginResult {
  success: boolean;
  result?: any;
  error?: string;
  metrics: {
    executionTime: number;
    memoryUsed: number;
    cpuTime: number;
  };
}

export class PluginRuntime extends EventEmitter {
  private isolates: Map<string, ivm.Isolate> = new Map();
  private contexts: Map<string, ivm.Context> = new Map();
  private logger: Logger;
  private metrics: MetricsCollector;

  constructor(logger: Logger, metrics: MetricsCollector) {
    super();
    this.logger = logger;
    this.metrics = metrics;
  }

  /**
   * Create a new V8 isolate for plugin execution
   */
  async createIsolate(pluginId: string, metadata: PluginMetadata): Promise<void> {
    try {
      // Create isolated V8 instance
      const isolate = new ivm.Isolate({
        memoryLimit: metadata.maxMemory || 128, // MB
        inspector: process.env.NODE_ENV === 'development',
      });

      // Create context within isolate
      const context = await isolate.createContext();
      const global = context.global;

      // Set up secure globals
      await this.setupSecureGlobals(global, metadata);

      // Store isolate and context
      this.isolates.set(pluginId, isolate);
      this.contexts.set(pluginId, context);

      this.logger.info('Plugin isolate created', { pluginId, memoryLimit: metadata.maxMemory });

    } catch (error) {
      this.logger.error('Failed to create plugin isolate', { pluginId, error });
      throw error;
    }
  }

  /**
   * Execute plugin code within its isolate
   */
  async executePlugin(
    pluginId: string,
    code: string,
    functionName: string,
    args: any[],
    context: PluginContext
  ): Promise<PluginResult> {
    const startTime = Date.now();
    const isolate = this.isolates.get(pluginId);
    const vmContext = this.contexts.get(pluginId);

    if (!isolate || !vmContext) {
      throw new Error(`Plugin isolate not found: ${pluginId}`);
    }

    try {
      // Compile the plugin code
      const script = await isolate.compileScript(this.wrapPluginCode(code, context));

      // Set CPU time limit
      const cpuStartTime = isolate.cpuTime;
      const maxCpuTime = context.metadata.maxCpuTime || 1000; // milliseconds

      // Execute with timeout
      const result = await Promise.race([
        script.run(vmContext, { timeout: maxCpuTime }),
        this.createTimeoutPromise(maxCpuTime),
      ]);

      // Calculate metrics
      const executionTime = Date.now() - startTime;
      const cpuTime = isolate.cpuTime - cpuStartTime;
      const memoryUsed = isolate.getHeapStatistics().used_heap_size;

      // Validate result
      const pluginResult = await this.validateAndExtractResult(
        result,
        functionName,
        args,
        vmContext
      );

      // Update metrics
      this.metrics.recordPluginExecution(pluginId, {
        executionTime,
        cpuTime,
        memoryUsed,
        success: true,
      });

      this.logger.debug('Plugin executed successfully', {
        pluginId,
        functionName,
        executionTime,
        cpuTime,
        memoryUsed,
      });

      return {
        success: true,
        result: pluginResult,
        metrics: {
          executionTime,
          memoryUsed,
          cpuTime,
        },
      };

    } catch (error) {
      const executionTime = Date.now() - startTime;

      this.metrics.recordPluginExecution(pluginId, {
        executionTime,
        cpuTime: 0,
        memoryUsed: 0,
        success: false,
        error: error.message,
      });

      this.logger.error('Plugin execution failed', {
        pluginId,
        functionName,
        error: error.message,
        executionTime,
      });

      return {
        success: false,
        error: error.message,
        metrics: {
          executionTime,
          memoryUsed: 0,
          cpuTime: 0,
        },
      };
    }
  }

  /**
   * Set up secure global objects in the plugin context
   */
  private async setupSecureGlobals(global: ivm.Reference<any>, metadata: PluginMetadata): Promise<void> {
    // Basic JavaScript objects
    await global.set('Object', ivm.Reference.from(Object));
    await global.set('Array', ivm.Reference.from(Array));
    await global.set('String', ivm.Reference.from(String));
    await global.set('Number', ivm.Reference.from(Number));
    await global.set('Boolean', ivm.Reference.from(Boolean));
    await global.set('Date', ivm.Reference.from(Date));
    await global.set('Math', ivm.Reference.from(Math));
    await global.set('JSON', ivm.Reference.from(JSON));
    await global.set('RegExp', ivm.Reference.from(RegExp));

    // Console (limited)
    await global.set('console', ivm.Reference.from({
      log: this.createSecureConsole('log'),
      warn: this.createSecureConsole('warn'),
      error: this.createSecureConsole('error'),
      debug: this.createSecureConsole('debug'),
    }));

    // Plugin API based on permissions
    if (metadata.permissions.includes('email:read')) {
      await global.set('Email', ivm.Reference.from(this.createEmailAPI()));
    }

    if (metadata.permissions.includes('http:request')) {
      await global.set('Http', ivm.Reference.from(this.createHttpAPI()));
    }

    if (metadata.permissions.includes('storage:read') || metadata.permissions.includes('storage:write')) {
      await global.set('Storage', ivm.Reference.from(this.createStorageAPI(metadata.permissions)));
    }

    // Plugin utilities
    await global.set('Utils', ivm.Reference.from(this.createUtilsAPI()));
  }

  /**
   * Create secure console API
   */
  private createSecureConsole(level: string) {
    return (...args: any[]) => {
      const message = args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
      ).join(' ');
      
      this.logger[level](`Plugin Console: ${message}`);
    };
  }

  /**
   * Create Email API for plugins
   */
  private createEmailAPI() {
    return {
      getHeader: (name: string) => {
        // Implementation to get email header
        return null;
      },
      getBody: () => {
        // Implementation to get email body
        return '';
      },
      getAttachments: () => {
        // Implementation to get attachments
        return [];
      },
      addTag: (tag: string) => {
        // Implementation to add tag
        return true;
      },
      setStatus: (status: string) => {
        // Implementation to set status
        return true;
      },
    };
  }

  /**
   * Create HTTP API for plugins (limited)
   */
  private createHttpAPI() {
    return {
      get: async (url: string, options?: any) => {
        // Validate URL is allowed
        if (!this.isUrlAllowed(url)) {
          throw new Error('URL not allowed');
        }
        // Implementation for HTTP GET
        return { status: 200, data: {} };
      },
      post: async (url: string, data: any, options?: any) => {
        if (!this.isUrlAllowed(url)) {
          throw new Error('URL not allowed');
        }
        // Implementation for HTTP POST
        return { status: 200, data: {} };
      },
    };
  }

  /**
   * Create Storage API for plugins
   */
  private createStorageAPI(permissions: string[]) {
    const canRead = permissions.includes('storage:read');
    const canWrite = permissions.includes('storage:write');

    return {
      get: canRead ? async (key: string) => {
        // Implementation for storage get
        return null;
      } : undefined,
      set: canWrite ? async (key: string, value: any) => {
        // Implementation for storage set
        return true;
      } : undefined,
      delete: canWrite ? async (key: string) => {
        // Implementation for storage delete
        return true;
      } : undefined,
    };
  }

  /**
   * Create utility functions for plugins
   */
  private createUtilsAPI() {
    return {
      hash: (input: string, algorithm = 'sha256') => {
        // Implementation for secure hashing
        return '';
      },
      base64Encode: (input: string) => {
        return Buffer.from(input).toString('base64');
      },
      base64Decode: (input: string) => {
        return Buffer.from(input, 'base64').toString();
      },
      validateEmail: (email: string) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
      },
      validateUrl: (url: string) => {
        try {
          new URL(url);
          return true;
        } catch {
          return false;
        }
      },
    };
  }

  /**
   * Wrap plugin code with security and context
   */
  private wrapPluginCode(code: string, context: PluginContext): string {
    return `
      (function() {
        'use strict';
        
        // Plugin context
        const __context = ${JSON.stringify(context)};
        
        // User plugin code
        ${code}
        
        // Export the main function
        if (typeof main === 'function') {
          return main;
        } else {
          throw new Error('Plugin must export a main function');
        }
      })();
    `;
  }

  /**
   * Validate and extract result from plugin execution
   */
  private async validateAndExtractResult(
    result: any,
    functionName: string,
    args: any[],
    context: ivm.Context
  ): Promise<any> {
    // Execute the function with provided arguments
    const functionCall = `
      (function() {
        const fn = arguments[0];
        const args = Array.prototype.slice.call(arguments, 1);
        return fn.apply(null, args);
      })
    `;

    const script = await context.global.get('script');
    return await script.run(context, { arguments: [result, ...args] });
  }

  /**
   * Create timeout promise for CPU time limits
   */
  private createTimeoutPromise(timeout: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Plugin execution timed out after ${timeout}ms`));
      }, timeout);
    });
  }

  /**
   * Check if URL is allowed for HTTP requests
   */
  private isUrlAllowed(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      
      // Block private/internal addresses
      const hostname = parsedUrl.hostname;
      if (
        hostname === 'localhost' ||
        hostname.startsWith('127.') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('172.') ||
        hostname.startsWith('192.168.') ||
        hostname.includes('internal')
      ) {
        return false;
      }

      // Only allow HTTPS
      if (parsedUrl.protocol !== 'https:') {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Dispose of plugin isolate
   */
  async disposePlugin(pluginId: string): Promise<void> {
    const isolate = this.isolates.get(pluginId);
    const context = this.contexts.get(pluginId);

    if (context) {
      context.dispose();
      this.contexts.delete(pluginId);
    }

    if (isolate) {
      isolate.dispose();
      this.isolates.delete(pluginId);
    }

    this.logger.info('Plugin isolate disposed', { pluginId });
  }

  /**
   * Get plugin resource usage
   */
  getPluginStats(pluginId: string): any {
    const isolate = this.isolates.get(pluginId);
    if (!isolate) {
      return null;
    }

    return {
      heapStats: isolate.getHeapStatistics(),
      cpuTime: isolate.cpuTime,
      wallTime: isolate.wallTime,
    };
  }

  /**
   * Cleanup all plugins
   */
  async cleanup(): Promise<void> {
    const pluginIds = Array.from(this.isolates.keys());
    await Promise.all(pluginIds.map(id => this.disposePlugin(id)));
    
    this.logger.info('Plugin runtime cleanup completed');
  }
}