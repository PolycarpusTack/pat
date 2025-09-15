/**
 * Rate Limiter for SMTP connections
 * Uses Cloudflare KV for distributed rate limiting
 */

export interface RateLimitConfig {
  maxConnectionsPerIP: number;
  maxEmailsPerHour: number;
}

export interface RateLimitEntry {
  connections: number;
  emails: number;
  windowStart: number;
  blocked: boolean;
  blockUntil?: number;
}

export class RateLimiter {
  private kv: KVNamespace;
  private config: RateLimitConfig;
  private windowSize = 3600000; // 1 hour in milliseconds

  constructor(kv: KVNamespace, config: RateLimitConfig) {
    this.kv = kv;
    this.config = config;
  }

  async checkLimit(clientIp: string): Promise<boolean> {
    const key = `ratelimit:${clientIp}`;
    const now = Date.now();

    // Get current rate limit entry
    const entry = await this.getEntry(key);

    // Check if IP is blocked
    if (entry.blocked && entry.blockUntil && entry.blockUntil > now) {
      return false;
    }

    // Reset window if expired
    if (now - entry.windowStart > this.windowSize) {
      entry.connections = 0;
      entry.emails = 0;
      entry.windowStart = now;
      entry.blocked = false;
      entry.blockUntil = undefined;
    }

    // Check connection limit
    if (entry.connections >= this.config.maxConnectionsPerIP) {
      // Block for 5 minutes
      entry.blocked = true;
      entry.blockUntil = now + 300000;
      await this.saveEntry(key, entry);
      return false;
    }

    // Increment connection count
    entry.connections++;
    await this.saveEntry(key, entry);

    return true;
  }

  async recordEmail(clientIp: string): Promise<boolean> {
    const key = `ratelimit:${clientIp}`;
    const now = Date.now();

    const entry = await this.getEntry(key);

    // Check email limit
    if (entry.emails >= this.config.maxEmailsPerHour) {
      return false;
    }

    entry.emails++;
    await this.saveEntry(key, entry);

    return true;
  }

  async releaseConnection(clientIp: string): Promise<void> {
    const key = `ratelimit:${clientIp}`;
    const entry = await this.getEntry(key);

    if (entry.connections > 0) {
      entry.connections--;
      await this.saveEntry(key, entry);
    }
  }

  private async getEntry(key: string): Promise<RateLimitEntry> {
    const stored = await this.kv.get(key, { type: 'json' });
    
    if (stored) {
      return stored as RateLimitEntry;
    }

    return {
      connections: 0,
      emails: 0,
      windowStart: Date.now(),
      blocked: false,
    };
  }

  private async saveEntry(key: string, entry: RateLimitEntry): Promise<void> {
    // Store with TTL of 2 hours (to handle window rotation)
    await this.kv.put(key, JSON.stringify(entry), {
      expirationTtl: 7200,
    });
  }

  async getStats(clientIp: string): Promise<RateLimitEntry | null> {
    const key = `ratelimit:${clientIp}`;
    return await this.kv.get(key, { type: 'json' });
  }

  async resetLimit(clientIp: string): Promise<void> {
    const key = `ratelimit:${clientIp}`;
    await this.kv.delete(key);
  }
}