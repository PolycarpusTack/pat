/**
 * SMTP Protocol State Machine for Edge Workers
 */

export interface SMTPConfig {
  hostname: string;
  maxMessageSize: number;
  maxRecipients: number;
  timeout: number;
}

export interface SMTPCommand {
  verb: string;
  args: string;
  raw: string;
}

export interface SMTPResponse {
  code: number;
  message: string;
  multiline?: string[];
}

export interface SMTPSessionState {
  state: 'INIT' | 'READY' | 'MAIL' | 'RCPT' | 'DATA' | 'QUIT';
  helo?: string;
  from?: string;
  recipients: string[];
  authenticated: boolean;
  tls: boolean;
  extensions: string[];
}

export class SMTPStateMachine {
  public config: SMTPConfig;
  private session: SMTPSessionState;

  constructor(config: SMTPConfig) {
    this.config = config;
    this.session = {
      state: 'INIT',
      recipients: [],
      authenticated: false,
      tls: false,
      extensions: [
        'PIPELINING',
        '8BITMIME',
        `SIZE ${config.maxMessageSize}`,
        'ENHANCEDSTATUSCODES',
        'STARTTLS',
        'AUTH PLAIN LOGIN',
      ],
    };
  }

  async handleCommand(command: SMTPCommand): Promise<SMTPResponse> {
    // Validate command
    if (!command.verb) {
      return {
        code: 500,
        message: '5.5.2 Syntax error: empty command',
      };
    }

    // Route command to handler
    switch (command.verb) {
      case 'HELO':
        return this.handleHELO(command.args);
      case 'EHLO':
        return this.handleEHLO(command.args);
      case 'STARTTLS':
        return this.handleSTARTTLS();
      case 'AUTH':
        return this.handleAUTH(command.args);
      case 'MAIL':
        return this.handleMAIL(command.args);
      case 'RCPT':
        return this.handleRCPT(command.args);
      case 'DATA':
        return this.handleDATA();
      case 'RSET':
        return this.handleRSET();
      case 'NOOP':
        return this.handleNOOP();
      case 'QUIT':
        return this.handleQUIT();
      case 'VRFY':
      case 'EXPN':
        return {
          code: 502,
          message: '5.5.1 Command not implemented',
        };
      default:
        return {
          code: 500,
          message: '5.5.2 Syntax error: command unrecognized',
        };
    }
  }

  private handleHELO(domain: string): SMTPResponse {
    if (!domain) {
      return {
        code: 501,
        message: '5.5.4 Syntax error in HELO parameter',
      };
    }

    this.session.helo = domain;
    this.session.state = 'READY';

    return {
      code: 250,
      message: `${this.config.hostname} Hello ${domain}`,
    };
  }

  private handleEHLO(domain: string): SMTPResponse {
    if (!domain) {
      return {
        code: 501,
        message: '5.5.4 Syntax error in EHLO parameter',
      };
    }

    this.session.helo = domain;
    this.session.state = 'READY';

    const lines = [
      `${this.config.hostname} Hello ${domain}`,
      ...this.session.extensions,
    ];

    return {
      code: 250,
      message: lines[0],
      multiline: lines.slice(1),
    };
  }

  private handleSTARTTLS(): SMTPResponse {
    if (this.session.tls) {
      return {
        code: 454,
        message: '4.7.0 TLS already active',
      };
    }

    // In edge context, TLS is handled by Cloudflare
    return {
      code: 220,
      message: '2.0.0 Ready to start TLS',
    };
  }

  private handleAUTH(args: string): SMTPResponse {
    if (!args) {
      return {
        code: 501,
        message: '5.5.4 Syntax error in AUTH parameter',
      };
    }

    const [mechanism, ...credentials] = args.split(' ');

    // Edge authentication is delegated to backend
    // For now, accept all AUTH attempts
    this.session.authenticated = true;

    return {
      code: 235,
      message: '2.7.0 Authentication successful',
    };
  }

  private handleMAIL(args: string): SMTPResponse {
    if (this.session.state !== 'READY') {
      return {
        code: 503,
        message: '5.5.1 Bad sequence of commands',
      };
    }

    if (!args.toUpperCase().startsWith('FROM:')) {
      return {
        code: 501,
        message: '5.5.4 Syntax error in MAIL parameter',
      };
    }

    const from = this.extractAddress(args.substring(5));
    if (from === null) {
      return {
        code: 501,
        message: '5.1.7 Invalid address',
      };
    }

    this.session.from = from;
    this.session.state = 'MAIL';

    return {
      code: 250,
      message: '2.1.0 Sender OK',
    };
  }

  private handleRCPT(args: string): SMTPResponse {
    if (this.session.state !== 'MAIL' && this.session.state !== 'RCPT') {
      return {
        code: 503,
        message: '5.5.1 Bad sequence of commands',
      };
    }

    if (!args.toUpperCase().startsWith('TO:')) {
      return {
        code: 501,
        message: '5.5.4 Syntax error in RCPT parameter',
      };
    }

    const to = this.extractAddress(args.substring(3));
    if (to === null) {
      return {
        code: 501,
        message: '5.1.3 Invalid address',
      };
    }

    if (this.session.recipients.length >= this.config.maxRecipients) {
      return {
        code: 452,
        message: '4.5.3 Too many recipients',
      };
    }

    this.session.recipients.push(to);
    this.session.state = 'RCPT';

    return {
      code: 250,
      message: '2.1.5 Recipient OK',
    };
  }

  private handleDATA(): SMTPResponse {
    if (this.session.state !== 'RCPT') {
      return {
        code: 503,
        message: '5.5.1 Bad sequence of commands',
      };
    }

    if (this.session.recipients.length === 0) {
      return {
        code: 554,
        message: '5.5.1 No valid recipients',
      };
    }

    this.session.state = 'DATA';

    return {
      code: 354,
      message: 'Start mail input; end with <CRLF>.<CRLF>',
    };
  }

  private handleRSET(): SMTPResponse {
    this.resetSession();
    return {
      code: 250,
      message: '2.0.0 OK',
    };
  }

  private handleNOOP(): SMTPResponse {
    return {
      code: 250,
      message: '2.0.0 OK',
    };
  }

  private handleQUIT(): SMTPResponse {
    this.session.state = 'QUIT';
    return {
      code: 221,
      message: '2.0.0 Bye',
    };
  }

  private extractAddress(input: string): string | null {
    input = input.trim();
    
    // Handle null sender
    if (input === '<>') {
      return '';
    }

    // Extract address from angle brackets
    const match = input.match(/<([^>]+)>/);
    if (match) {
      return match[1].trim();
    }

    // If no angle brackets, validate as email
    if (this.isValidEmail(input)) {
      return input;
    }

    return null;
  }

  private isValidEmail(email: string): boolean {
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private resetSession(): void {
    this.session.from = undefined;
    this.session.recipients = [];
    this.session.state = this.session.helo ? 'READY' : 'INIT';
  }

  public getSessionInfo(): SMTPSessionState {
    return { ...this.session };
  }
}