import { GraphQLResolveInfo } from 'graphql';
import { DateTimeResolver, JSONResolver } from 'graphql-scalars';
import { GraphQLUpload } from 'graphql-upload-ts';
import { merge } from 'lodash';

import { emailResolvers } from './email';
import { workflowResolvers } from './workflow';
import { pluginResolvers } from './plugin';
import { templateResolvers } from './template';
import { userResolvers } from './user';
import { webhookResolvers } from './webhook';
import { subscriptionResolvers } from './subscription';
import { Context } from '../context';

// Custom scalar resolvers
const scalarResolvers = {
  DateTime: DateTimeResolver,
  JSON: JSONResolver,
  Upload: GraphQLUpload,
};

// Merge all resolvers
export const resolvers = merge(
  scalarResolvers,
  emailResolvers,
  workflowResolvers,
  pluginResolvers,
  templateResolvers,
  userResolvers,
  webhookResolvers,
  subscriptionResolvers,
  {
    Query: {
      // System stats resolver
      systemStats: async (
        parent: any,
        args: { startDate?: Date; endDate?: Date },
        context: Context,
        info: GraphQLResolveInfo
      ) => {
        const { startDate, endDate } = args;
        const { services } = context;

        const [emails, storage, performance] = await Promise.all([
          services.stats.getEmailStats(startDate, endDate),
          services.stats.getStorageStats(),
          services.stats.getPerformanceStats(),
        ]);

        return {
          emails,
          storage,
          performance,
        };
      },
    },
  }
);