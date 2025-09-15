import { ApolloServerPlugin, GraphQLRequestListener } from '@apollo/server';
import { GraphQLError } from 'graphql';
import { Context } from './context';
import { logger } from '../../pkg/logger';
import { v4 as uuidv4 } from 'uuid';

// Request logging plugin
export const loggingPlugin: ApolloServerPlugin<Context> = {
  async requestDidStart() {
    const requestId = uuidv4();
    const startTime = Date.now();

    return {
      async willSendResponse(requestContext) {
        const duration = Date.now() - startTime;
        const { request, response } = requestContext;
        
        logger.info('GraphQL Request', {
          requestId,
          operationName: request.operationName,
          query: request.query,
          variables: request.variables,
          duration,
          status: response.body.singleResult.errors ? 'error' : 'success',
          errors: response.body.singleResult.errors,
        });
      },

      async didEncounterErrors(requestContext) {
        const { errors } = requestContext;
        
        errors.forEach(error => {
          logger.error('GraphQL Error', {
            requestId,
            message: error.message,
            path: error.path,
            extensions: error.extensions,
            stack: error.stack,
          });
        });
      },
    };
  },
};

// Performance monitoring plugin
export const performancePlugin: ApolloServerPlugin<Context> = {
  async requestDidStart() {
    const fieldTimings = new Map<string, number>();

    return {
      async executionDidStart() {
        return {
          willResolveField({ info }) {
            const start = Date.now();
            const fieldName = `${info.parentType.name}.${info.fieldName}`;

            return () => {
              const duration = Date.now() - start;
              fieldTimings.set(fieldName, duration);
            };
          },
        };
      },

      async willSendResponse(requestContext) {
        // Log slow fields
        const slowFields = Array.from(fieldTimings.entries())
          .filter(([_, duration]) => duration > 100)
          .sort((a, b) => b[1] - a[1]);

        if (slowFields.length > 0) {
          logger.warn('Slow GraphQL fields detected', {
            operationName: requestContext.request.operationName,
            slowFields: slowFields.map(([field, duration]) => ({
              field,
              duration,
            })),
          });
        }
      },
    };
  },
};

// Query complexity plugin
export const complexityPlugin: ApolloServerPlugin<Context> = {
  async requestDidStart() {
    return {
      async validationDidStart() {
        return async (validationContext) => {
          const { document, schema } = validationContext;
          
          // Calculate query complexity
          // This is a simplified version - use graphql-query-complexity in production
          let complexity = 0;
          
          // Walk through the document and calculate complexity
          // ... implementation details ...
          
          if (complexity > 1000) {
            throw new GraphQLError('Query too complex', {
              extensions: {
                code: 'QUERY_TOO_COMPLEX',
                complexity,
                limit: 1000,
              },
            });
          }
        };
      },
    };
  },
};

// Caching plugin
export const cachingPlugin: ApolloServerPlugin<Context> = {
  async requestDidStart() {
    return {
      async willSendResponse(requestContext) {
        const { response, request } = requestContext;
        
        // Don't cache mutations or subscriptions
        if (request.query?.includes('mutation') || request.query?.includes('subscription')) {
          return;
        }
        
        // Don't cache if there are errors
        if (response.body.singleResult.errors) {
          return;
        }
        
        // Set cache headers
        response.http.headers.set('Cache-Control', 'max-age=60, stale-while-revalidate=30');
        
        // Add ETag
        const content = JSON.stringify(response.body.singleResult.data);
        const etag = `"${Buffer.from(content).toString('base64').substring(0, 27)}"`;
        response.http.headers.set('ETag', etag);
      },
    };
  },
};

// Error tracking plugin (e.g., Sentry)
export const errorTrackingPlugin: ApolloServerPlugin<Context> = {
  async requestDidStart() {
    return {
      async didEncounterErrors(requestContext) {
        const { errors, request, contextValue } = requestContext;
        
        // Send errors to error tracking service
        errors.forEach(error => {
          // In production, use Sentry or similar
          console.error('Error to track:', {
            error: error.message,
            path: error.path,
            user: contextValue.user,
            operation: request.operationName,
            query: request.query,
            variables: request.variables,
          });
        });
      },
    };
  },
};

// Telemetry plugin
export const telemetryPlugin: ApolloServerPlugin<Context> = {
  async serverWillStart() {
    logger.info('GraphQL server starting');
    
    return {
      async serverWillStop() {
        logger.info('GraphQL server stopping');
      },
    };
  },

  async requestDidStart() {
    const metrics = {
      operationCount: 0,
      fieldCount: 0,
      errorCount: 0,
    };

    return {
      async executionDidStart() {
        metrics.operationCount++;
        
        return {
          willResolveField() {
            metrics.fieldCount++;
          },
        };
      },

      async didEncounterErrors({ errors }) {
        metrics.errorCount += errors.length;
      },

      async willSendResponse() {
        // Send metrics to monitoring service
        // In production, use Prometheus, DataDog, etc.
        if (process.env.METRICS_ENABLED === 'true') {
          console.log('GraphQL Metrics:', metrics);
        }
      },
    };
  },
};

// Export all plugins
export const plugins = [
  loggingPlugin,
  performancePlugin,
  complexityPlugin,
  cachingPlugin,
  errorTrackingPlugin,
  telemetryPlugin,
];