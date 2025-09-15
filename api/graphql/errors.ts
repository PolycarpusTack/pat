import { GraphQLError } from 'graphql';
import { ApolloServerErrorCode } from '@apollo/server/errors';

// Custom error classes
export class ValidationError extends GraphQLError {
  constructor(message: string, extensions?: Record<string, any>) {
    super(message, {
      extensions: {
        code: 'VALIDATION_ERROR',
        ...extensions,
      },
    });
  }
}

export class AuthenticationError extends GraphQLError {
  constructor(message: string = 'Authentication required') {
    super(message, {
      extensions: {
        code: 'UNAUTHENTICATED',
      },
    });
  }
}

export class ForbiddenError extends GraphQLError {
  constructor(message: string = 'Access denied') {
    super(message, {
      extensions: {
        code: 'FORBIDDEN',
      },
    });
  }
}

export class NotFoundError extends GraphQLError {
  constructor(message: string = 'Resource not found') {
    super(message, {
      extensions: {
        code: 'NOT_FOUND',
      },
    });
  }
}

export class ConflictError extends GraphQLError {
  constructor(message: string) {
    super(message, {
      extensions: {
        code: 'CONFLICT',
      },
    });
  }
}

export class RateLimitError extends GraphQLError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, {
      extensions: {
        code: 'RATE_LIMITED',
      },
    });
  }
}

export class InternalError extends GraphQLError {
  constructor(message: string = 'Internal server error', originalError?: Error) {
    super(message, {
      extensions: {
        code: 'INTERNAL_SERVER_ERROR',
        originalError: originalError?.message,
      },
    });
  }
}

// Error formatter for Apollo Server
export function formatError(formattedError: GraphQLError, error: unknown): GraphQLError {
  // Log internal errors
  if (formattedError.extensions?.code === ApolloServerErrorCode.INTERNAL_SERVER_ERROR) {
    console.error('Internal server error:', error);
  }

  // Remove stack traces in production
  if (process.env.NODE_ENV === 'production') {
    delete formattedError.extensions?.stacktrace;
    delete formattedError.extensions?.originalError;
  }

  // Add request ID if available
  const requestId = (error as any)?.extensions?.requestId;
  if (requestId) {
    formattedError.extensions = {
      ...formattedError.extensions,
      requestId,
    };
  }

  return formattedError;
}

// Error logging middleware
export function logError(error: Error, context?: any): void {
  const errorInfo = {
    message: error.message,
    stack: error.stack,
    context,
    timestamp: new Date().toISOString(),
  };

  if (error instanceof GraphQLError) {
    errorInfo.extensions = error.extensions;
  }

  console.error('GraphQL Error:', JSON.stringify(errorInfo, null, 2));
}

// Validation helpers
export function validateEmail(email: string): void {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ValidationError('Invalid email address');
  }
}

export function validateUrl(url: string): void {
  try {
    new URL(url);
  } catch {
    throw new ValidationError('Invalid URL');
  }
}

export function validatePagination(first?: number, last?: number): void {
  if (first !== undefined && first < 1) {
    throw new ValidationError('First must be greater than 0');
  }
  if (last !== undefined && last < 1) {
    throw new ValidationError('Last must be greater than 0');
  }
  if (first !== undefined && first > 100) {
    throw new ValidationError('First cannot exceed 100');
  }
  if (last !== undefined && last > 100) {
    throw new ValidationError('Last cannot exceed 100');
  }
}