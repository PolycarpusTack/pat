/**
 * Cloudflare Worker for SMTP edge processing
 * Handles TCP-over-WebSocket bridge for global SMTP ingestion
 */

import { SMTPStateMachine, SMTPCommand, SMTPResponse } from './smtp';
import { RateLimiter } from './rate-limiter';
import { GeoRouter } from './geo-router';

export interface Env {
  // KV namespaces
  RATE_LIMIT: KVNamespace;
  GEO_ROUTING: KVNamespace;
  
  // Durable Objects
  SMTP_SESSION: DurableObjectNamespace;
  
  // Environment variables
  BACKEND_URL: string;
  MAX_CONNECTIONS_PER_IP: string;
  MAX_EMAILS_PER_HOUR: string;
  ALLOWED_DOMAINS: string;
}

// WebSocket message types
interface WSMessage {
  type: 'data' | 'close' | 'error';
  data?: Uint8Array;
  error?: string;
}

// SMTP Session Durable Object
export class SMTPSession {
  private state: DurableObjectState;
  private env: Env;
  private websocket?: WebSocket;
  private stateMachine: SMTPStateMachine;
  private sessionId: string;
  private remoteIp: string;
  private startTime: number;
  private bytesReceived: number = 0;
  private bytesSent: number = 0;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sessionId = crypto.randomUUID();
    this.startTime = Date.now();
    this.stateMachine = new SMTPStateMachine({
      hostname: 'mx.pat.email',
      maxMessageSize: 50 * 1024 * 1024, // 50MB
      maxRecipients: 100,
      timeout: 300000, // 5 minutes
    });
  }

  async fetch(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair());
    this.websocket = server;
    this.remoteIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Accept WebSocket
    server.accept();

    // Handle WebSocket events
    server.addEventListener('message', (event) => this.handleMessage(event));
    server.addEventListener('close', () => this.handleClose());
    server.addEventListener('error', (error) => this.handleError(error));

    // Send initial SMTP greeting
    await this.sendSMTPResponse({
      code: 220,
      message: `${this.stateMachine.config.hostname} ESMTP Pat Edge Server`,
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private async handleMessage(event: MessageEvent) {
    try {
      const message: WSMessage = JSON.parse(event.data as string);
      
      if (message.type === 'data' && message.data) {
        const data = new Uint8Array(message.data);
        this.bytesReceived += data.length;
        
        // Process SMTP data
        const commands = this.parseCommands(data);
        for (const command of commands) {
          await this.processSMTPCommand(command);
        }
      } else if (message.type === 'close') {
        await this.handleClose();
      }
    } catch (error) {
      console.error('Error handling message:', error);
      await this.sendError('Internal server error');
    }
  }

  private parseCommands(data: Uint8Array): SMTPCommand[] {
    // Convert bytes to string and split by CRLF
    const text = new TextDecoder().decode(data);
    const lines = text.split('\r\n').filter(line => line.length > 0);
    
    return lines.map(line => {
      const [verb, ...args] = line.split(' ');
      return {
        verb: verb.toUpperCase(),
        args: args.join(' '),
        raw: line,
      };
    });
  }

  private async processSMTPCommand(command: SMTPCommand) {
    console.log(`SMTP Command: ${command.verb} ${command.args}`);
    
    try {
      const response = await this.stateMachine.handleCommand(command);
      await this.sendSMTPResponse(response);
      
      // Handle special commands
      switch (command.verb) {
        case 'DATA':
          if (response.code === 354) {
            // Switch to DATA mode
            await this.handleDataMode();
          }
          break;
          
        case 'QUIT':
          if (response.code === 221) {
            await this.handleClose();
          }
          break;
      }
    } catch (error) {
      console.error('Error processing command:', error);
      await this.sendSMTPResponse({
        code: 421,
        message: 'Service temporarily unavailable',
      });
    }
  }

  private async handleDataMode() {
    // Collect email data until we see <CRLF>.<CRLF>
    const chunks: Uint8Array[] = [];
    let totalSize = 0;
    
    // This would be implemented with proper streaming
    // For now, simplified version
    const emailData = await this.collectEmailData();
    
    // Forward to backend
    const backendUrl = await this.getBackendUrl();
    const response = await fetch(`${backendUrl}/smtp/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Session-ID': this.sessionId,
        'X-Remote-IP': this.remoteIp,
        'X-Edge-Region': this.env.BACKEND_URL.includes('us-east') ? 'us-east-1' : 'us-west-2',
      },
      body: emailData,
    });
    
    if (response.ok) {
      const result = await response.json();
      await this.sendSMTPResponse({
        code: 250,
        message: `Message accepted for delivery: ${result.messageId}`,
      });
    } else {
      await this.sendSMTPResponse({
        code: 451,
        message: 'Failed to process message',
      });
    }
  }

  private async collectEmailData(): Promise<Uint8Array> {
    // Simplified email data collection
    // In production, this would handle streaming and proper termination detection
    return new Uint8Array();
  }

  private async sendSMTPResponse(response: SMTPResponse) {
    const message = `${response.code} ${response.message}\r\n`;
    const data = new TextEncoder().encode(message);
    this.bytesSent += data.length;
    
    if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
      const wsMessage: WSMessage = {
        type: 'data',
        data: Array.from(data),
      };
      this.websocket.send(JSON.stringify(wsMessage));
    }
  }

  private async sendError(error: string) {
    if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
      const wsMessage: WSMessage = {
        type: 'error',
        error,
      };
      this.websocket.send(JSON.stringify(wsMessage));
    }
  }

  private async handleClose() {
    // Log session metrics
    const duration = Date.now() - this.startTime;
    console.log('SMTP session closed', {
      sessionId: this.sessionId,
      duration,
      bytesReceived: this.bytesReceived,
      bytesSent: this.bytesSent,
      remoteIp: this.remoteIp,
    });
    
    // Clean up
    if (this.websocket) {
      this.websocket.close();
    }
  }

  private handleError(error: Event) {
    console.error('WebSocket error:', error);
    this.handleClose();
  }

  private async getBackendUrl(): Promise<string> {
    // Use geo-routing to select optimal backend
    const geoRouter = new GeoRouter(this.env.GEO_ROUTING);
    return await geoRouter.getOptimalBackend(this.remoteIp);
  }
}

// Main worker handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      // Rate limiting
      const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rateLimiter = new RateLimiter(env.RATE_LIMIT, {
        maxConnectionsPerIP: parseInt(env.MAX_CONNECTIONS_PER_IP || '10'),
        maxEmailsPerHour: parseInt(env.MAX_EMAILS_PER_HOUR || '1000'),
      });
      
      const allowed = await rateLimiter.checkLimit(clientIp);
      if (!allowed) {
        return new Response('Rate limit exceeded', { status: 429 });
      }
      
      // CORS headers for WebSocket
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Upgrade',
          },
        });
      }
      
      // Route to durable object
      const id = env.SMTP_SESSION.idFromName(crypto.randomUUID());
      const smtpSession = env.SMTP_SESSION.get(id);
      
      return await smtpSession.fetch(request);
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal server error', { status: 500 });
    }
  },
};