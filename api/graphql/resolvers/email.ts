import { GraphQLResolveInfo } from 'graphql';
import { Context } from '../context';
import { pubsub } from '../server';
import { ValidationError, NotFoundError } from '../errors';
import { EmailFilter, EmailConnection, CreateEmailInput, UpdateEmailInput } from '../types';

const EMAIL_RECEIVED = 'EMAIL_RECEIVED';
const EMAIL_STATUS_CHANGED = 'EMAIL_STATUS_CHANGED';

export const emailResolvers = {
  Query: {
    // Get single email by ID
    email: async (
      parent: any,
      args: { id: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id } = args;
      const { user, services, dataloaders } = context;

      // Use dataloader for efficiency
      const email = await dataloaders.emailById.load(id);
      
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canViewEmail(user, email)) {
        throw new NotFoundError('Email not found');
      }

      return email;
    },

    // Get paginated emails
    emails: async (
      parent: any,
      args: {
        filter?: EmailFilter;
        first?: number;
        after?: string;
        last?: number;
        before?: string;
        orderBy?: string;
        orderDirection?: 'ASC' | 'DESC';
      },
      context: Context,
      info: GraphQLResolveInfo
    ): Promise<EmailConnection> => {
      const { user, services } = context;
      const { filter = {}, first = 20, after, last, before, orderBy = 'receivedAt', orderDirection = 'DESC' } = args;

      // Validate pagination args
      if (first && last) {
        throw new ValidationError('Cannot specify both first and last');
      }
      if (after && before) {
        throw new ValidationError('Cannot specify both after and before');
      }

      // Build query options
      const limit = first || last || 20;
      const cursor = after || before;
      const reverse = !!last || !!before;

      // Execute query
      const result = await services.email.listEmails({
        tenantId: user.tenantId,
        filter,
        limit: limit + 1, // Fetch one extra to determine hasMore
        cursor,
        orderBy,
        orderDirection: reverse ? 
          (orderDirection === 'ASC' ? 'DESC' : 'ASC') : 
          orderDirection,
      });

      // Format as connection
      const hasMore = result.items.length > limit;
      const items = hasMore ? result.items.slice(0, -1) : result.items;
      
      if (reverse) {
        items.reverse();
      }

      const edges = items.map((email, index) => ({
        node: email,
        cursor: email.id,
      }));

      return {
        edges,
        pageInfo: {
          hasNextPage: reverse ? false : hasMore,
          hasPreviousPage: reverse ? hasMore : false,
          startCursor: edges[0]?.cursor,
          endCursor: edges[edges.length - 1]?.cursor,
        },
        totalCount: result.totalCount,
      };
    },

    // Search emails
    emailSearch: async (
      parent: any,
      args: { query: string; first?: number; after?: string },
      context: Context,
      info: GraphQLResolveInfo
    ): Promise<EmailConnection> => {
      const { query, first = 20, after } = args;
      const { user, services } = context;

      if (!query || query.trim().length < 3) {
        throw new ValidationError('Search query must be at least 3 characters');
      }

      const result = await services.email.searchEmails({
        tenantId: user.tenantId,
        query,
        limit: first + 1,
        cursor: after,
      });

      const hasMore = result.items.length > first;
      const items = hasMore ? result.items.slice(0, -1) : result.items;

      const edges = items.map(email => ({
        node: email,
        cursor: email.id,
      }));

      return {
        edges,
        pageInfo: {
          hasNextPage: hasMore,
          hasPreviousPage: false,
          startCursor: edges[0]?.cursor,
          endCursor: edges[edges.length - 1]?.cursor,
        },
        totalCount: result.totalCount,
      };
    },

    // Get email conversation
    emailConversation: async (
      parent: any,
      args: { conversationId: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { conversationId } = args;
      const { user, services } = context;

      const emails = await services.email.getConversation({
        tenantId: user.tenantId,
        conversationId,
      });

      // Filter emails user can view
      const viewableEmails = [];
      for (const email of emails) {
        if (await services.auth.canViewEmail(user, email)) {
          viewableEmails.push(email);
        }
      }

      return viewableEmails;
    },
  },

  Mutation: {
    // Create email
    createEmail: async (
      parent: any,
      args: { input: CreateEmailInput },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { input } = args;
      const { user, services } = context;

      // Validate input
      if (!input.to || input.to.length === 0) {
        throw new ValidationError('At least one recipient is required');
      }

      // Handle file uploads
      let attachments = [];
      if (input.attachments) {
        attachments = await Promise.all(
          input.attachments.map(async (upload) => {
            const file = await upload;
            return services.storage.uploadAttachment(file);
          })
        );
      }

      // Create email
      const email = await services.email.createEmail({
        ...input,
        attachments,
        tenantId: user.tenantId,
        createdBy: user.id,
      });

      // Publish event
      await pubsub.publish(EMAIL_RECEIVED, {
        emailReceived: email,
      });

      return email;
    },

    // Update email
    updateEmail: async (
      parent: any,
      args: { id: string; input: UpdateEmailInput },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id, input } = args;
      const { user, services } = context;

      // Get existing email
      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canUpdateEmail(user, email)) {
        throw new NotFoundError('Email not found');
      }

      // Update email
      const updatedEmail = await services.email.updateEmail(id, input);

      // Publish event if status changed
      if (input.status && input.status !== email.status) {
        await pubsub.publish(EMAIL_STATUS_CHANGED, {
          emailStatusChanged: updatedEmail,
        });
      }

      return updatedEmail;
    },

    // Delete email
    deleteEmail: async (
      parent: any,
      args: { id: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id } = args;
      const { user, services } = context;

      // Get existing email
      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canDeleteEmail(user, email)) {
        throw new NotFoundError('Email not found');
      }

      // Delete email
      await services.email.deleteEmail(id);

      return true;
    },

    // Tag email
    tagEmail: async (
      parent: any,
      args: { id: string; tags: string[] },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id, tags } = args;
      const { user, services } = context;

      // Validate tags
      if (!tags || tags.length === 0) {
        throw new ValidationError('At least one tag is required');
      }

      // Get email
      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canUpdateEmail(user, email)) {
        throw new NotFoundError('Email not found');
      }

      // Add tags
      return await services.email.addTags(id, tags);
    },

    // Untag email
    untagEmail: async (
      parent: any,
      args: { id: string; tags: string[] },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id, tags } = args;
      const { user, services } = context;

      // Get email
      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canUpdateEmail(user, email)) {
        throw new NotFoundError('Email not found');
      }

      // Remove tags
      return await services.email.removeTags(id, tags);
    },

    // Mark as spam
    markEmailAsSpam: async (
      parent: any,
      args: { id: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id } = args;
      const { user, services } = context;

      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Mark as spam and train spam filter
      await services.spam.markAsSpam(email);
      
      return await services.email.updateEmail(id, {
        metadata: {
          ...email.metadata,
          markedAsSpam: true,
          markedAsSpamBy: user.id,
          markedAsSpamAt: new Date().toISOString(),
        },
      });
    },

    // Mark as not spam
    markEmailAsNotSpam: async (
      parent: any,
      args: { id: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id } = args;
      const { user, services } = context;

      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Mark as not spam and train spam filter
      await services.spam.markAsNotSpam(email);
      
      return await services.email.updateEmail(id, {
        metadata: {
          ...email.metadata,
          markedAsSpam: false,
          markedAsNotSpamBy: user.id,
          markedAsNotSpamAt: new Date().toISOString(),
        },
      });
    },

    // Resend email
    resendEmail: async (
      parent: any,
      args: { id: string },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id } = args;
      const { user, services } = context;

      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canSendEmail(user)) {
        throw new NotFoundError('Email not found');
      }

      // Resend email
      return await services.email.resendEmail(id);
    },

    // Forward email
    forwardEmail: async (
      parent: any,
      args: { id: string; to: Array<{ address: string; name?: string }> },
      context: Context,
      info: GraphQLResolveInfo
    ) => {
      const { id, to } = args;
      const { user, services } = context;

      const email = await services.email.getEmail(id);
      if (!email) {
        throw new NotFoundError('Email not found');
      }

      // Check permissions
      if (!await services.auth.canSendEmail(user)) {
        throw new NotFoundError('Email not found');
      }

      // Forward email
      return await services.email.forwardEmail(id, to);
    },
  },

  // Field resolvers
  Email: {
    // Resolve attachments using dataloader
    attachments: async (email: any, args: any, context: Context) => {
      if (email.attachments) {
        return email.attachments;
      }
      return context.dataloaders.attachmentsByEmailId.load(email.id);
    },

    // Resolve conversation emails
    conversation: async (email: any, args: any, context: Context) => {
      if (!email.conversationId) {
        return [email];
      }
      return context.services.email.getConversation({
        tenantId: email.tenantId,
        conversationId: email.conversationId,
      });
    },

    // Generate attachment URLs
    attachmentUrls: async (email: any, args: any, context: Context) => {
      const attachments = await context.dataloaders.attachmentsByEmailId.load(email.id);
      return Promise.all(
        attachments.map(async (attachment: any) => ({
          ...attachment,
          url: await context.services.storage.getAttachmentUrl(attachment.s3Key),
        }))
      );
    },
  },
};