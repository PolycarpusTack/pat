import { APIGatewayProxyEvent, APIGatewayProxyResult, Context as LambdaContext } from 'aws-lambda';
import { ApolloServer } from '@apollo/server';
import { startServerAndCreateLambdaHandler } from '@aws-sdk/apollo-server-lambda';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { typeDefs } from './schema';
import { resolvers } from './resolvers';
import { createContext } from './context';
import { permissions } from './permissions';
import { plugins } from './plugins';
import { formatError } from './errors';

// Create schema
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Apply permissions
const schemaWithPermissions = permissions.generate(schema);

// Create Apollo Server
const server = new ApolloServer({
  schema: schemaWithPermissions,
  plugins,
  formatError,
  introspection: process.env.NODE_ENV !== 'production',
});

// Create Lambda handler
export const handler = startServerAndCreateLambdaHandler(
  server,
  {
    context: async ({ event, context }: { 
      event: APIGatewayProxyEvent; 
      context: LambdaContext 
    }) => {
      // Extract auth token
      const token = event.headers.Authorization || event.headers.authorization;
      
      // Create context
      return createContext({
        token,
        dataloaders: createDataLoaders(),
      });
    },
  }
);

// DataLoader creation (simplified for Lambda)
function createDataLoaders() {
  // In Lambda, we create fresh DataLoaders for each request
  return {
    emailById: new DataLoader(async (ids: string[]) => {
      // Implement batch loading
      return ids.map(id => ({ id }));
    }),
    userById: new DataLoader(async (ids: string[]) => {
      return ids.map(id => ({ id }));
    }),
    workflowById: new DataLoader(async (ids: string[]) => {
      return ids.map(id => ({ id }));
    }),
    attachmentsByEmailId: new DataLoader(async (emailIds: string[]) => {
      return emailIds.map(id => []);
    }),
  };
}