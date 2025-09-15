/**
 * Geo-based routing for optimal backend selection
 * Routes SMTP traffic to the nearest healthy backend
 */

export interface Backend {
  id: string;
  url: string;
  region: string;
  healthy: boolean;
  latency: number;
  capacity: number;
  currentLoad: number;
}

export interface GeoRoutingConfig {
  backends: Backend[];
  healthCheckInterval: number;
  maxLatency: number;
}

export class GeoRouter {
  private kv: KVNamespace;
  private backendsKey = 'geo:backends';
  private healthKey = 'geo:health';

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getOptimalBackend(clientIp: string): Promise<string> {
    // Get client location from Cloudflare headers
    // In a real worker, this would come from request.cf
    const clientRegion = await this.getClientRegion(clientIp);
    
    // Get available backends
    const backends = await this.getBackends();
    
    // Filter healthy backends
    const healthyBackends = backends.filter(b => b.healthy);
    
    if (healthyBackends.length === 0) {
      throw new Error('No healthy backends available');
    }
    
    // Sort by proximity and load
    const optimal = this.selectOptimalBackend(healthyBackends, clientRegion);
    
    // Update load tracking
    await this.incrementLoad(optimal.id);
    
    return optimal.url;
  }

  private async getClientRegion(clientIp: string): Promise<string> {
    // In production, use Cloudflare's geolocation
    // For now, return a default region
    return 'us-east-1';
  }

  private async getBackends(): Promise<Backend[]> {
    const stored = await this.kv.get(this.backendsKey, { type: 'json' });
    
    if (stored) {
      return stored as Backend[];
    }
    
    // Default backends
    return [
      {
        id: 'us-east-1',
        url: 'https://smtp-us-east-1.pat.email',
        region: 'us-east-1',
        healthy: true,
        latency: 10,
        capacity: 10000,
        currentLoad: 0,
      },
      {
        id: 'us-west-2',
        url: 'https://smtp-us-west-2.pat.email',
        region: 'us-west-2',
        healthy: true,
        latency: 15,
        capacity: 10000,
        currentLoad: 0,
      },
      {
        id: 'eu-west-1',
        url: 'https://smtp-eu-west-1.pat.email',
        region: 'eu-west-1',
        healthy: true,
        latency: 50,
        capacity: 10000,
        currentLoad: 0,
      },
      {
        id: 'ap-southeast-1',
        url: 'https://smtp-ap-southeast-1.pat.email',
        region: 'ap-southeast-1',
        healthy: true,
        latency: 80,
        capacity: 10000,
        currentLoad: 0,
      },
    ];
  }

  private selectOptimalBackend(backends: Backend[], clientRegion: string): Backend {
    // Score each backend based on:
    // 1. Regional proximity (highest weight)
    // 2. Current load percentage
    // 3. Latency
    
    const scored = backends.map(backend => {
      let score = 100;
      
      // Regional proximity
      if (backend.region === clientRegion) {
        score += 50;
      } else if (this.isSameContinent(backend.region, clientRegion)) {
        score += 25;
      }
      
      // Load percentage (prefer less loaded)
      const loadPercent = (backend.currentLoad / backend.capacity) * 100;
      score -= loadPercent * 0.5;
      
      // Latency penalty
      score -= backend.latency * 0.1;
      
      return { backend, score };
    });
    
    // Sort by score (highest first)
    scored.sort((a, b) => b.score - a.score);
    
    return scored[0].backend;
  }

  private isSameContinent(region1: string, region2: string): boolean {
    const continents: { [key: string]: string } = {
      'us-east-1': 'NA',
      'us-west-2': 'NA',
      'eu-west-1': 'EU',
      'eu-central-1': 'EU',
      'ap-southeast-1': 'AS',
      'ap-northeast-1': 'AS',
    };
    
    return continents[region1] === continents[region2];
  }

  private async incrementLoad(backendId: string): Promise<void> {
    const loadKey = `geo:load:${backendId}`;
    const current = await this.kv.get(loadKey, { type: 'json' }) || { count: 0 };
    
    await this.kv.put(loadKey, JSON.stringify({
      count: current.count + 1,
      timestamp: Date.now(),
    }), {
      expirationTtl: 300, // 5 minutes
    });
  }

  async updateHealth(backendId: string, healthy: boolean, latency?: number): Promise<void> {
    const backends = await this.getBackends();
    const backend = backends.find(b => b.id === backendId);
    
    if (backend) {
      backend.healthy = healthy;
      if (latency !== undefined) {
        backend.latency = latency;
      }
      
      await this.kv.put(this.backendsKey, JSON.stringify(backends), {
        expirationTtl: 3600, // 1 hour
      });
    }
  }

  async performHealthChecks(): Promise<void> {
    const backends = await this.getBackends();
    
    const checks = backends.map(async (backend) => {
      try {
        const start = Date.now();
        const response = await fetch(`${backend.url}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000),
        });
        
        const latency = Date.now() - start;
        const healthy = response.ok;
        
        await this.updateHealth(backend.id, healthy, latency);
      } catch (error) {
        await this.updateHealth(backend.id, false);
      }
    });
    
    await Promise.all(checks);
  }
}