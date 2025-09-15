/**
 * Webhook Notifier Plugin
 * 
 * Sends webhook notifications to external services when emails are received or processed.
 * Supports multiple webhook endpoints, filtering, and retry logic.
 * 
 * @author Pat Team
 * @version 1.0.0
 * @permissions email:read, http:request, storage:read, storage:write
 * @hooks email.received, email.processed, email.sent
 */

function main(hook, payload) {
    try {
        console.log('Webhook notifier triggered for hook:', hook);

        // Get webhook configuration
        const config = getWebhookConfig();
        
        if (!config.enabled) {
            console.log('Webhook notifications are disabled');
            return { success: true, result: { action: 'disabled' } };
        }

        // Filter webhooks for this hook
        const relevantWebhooks = config.webhooks.filter(webhook => 
            webhook.enabled && webhook.hooks.includes(hook)
        );

        if (relevantWebhooks.length === 0) {
            console.log('No webhooks configured for hook:', hook);
            return { success: true, result: { action: 'no_webhooks' } };
        }

        console.log(`Found ${relevantWebhooks.length} webhooks for hook: ${hook}`);

        // Prepare notification payload
        const notificationPayload = preparePayload(hook, payload, config);
        
        // Send to each webhook
        const results = [];
        let successCount = 0;
        let failureCount = 0;

        for (const webhook of relevantWebhooks) {
            // Check if webhook conditions are met
            if (!evaluateWebhookConditions(webhook, payload)) {
                console.log('Webhook conditions not met for:', webhook.name);
                results.push({
                    webhook_id: webhook.id,
                    webhook_name: webhook.name,
                    status: 'skipped',
                    reason: 'conditions_not_met'
                });
                continue;
            }

            // Check rate limiting
            const rateLimitCheck = checkWebhookRateLimit(webhook);
            if (!rateLimitCheck.allowed) {
                console.log('Rate limit exceeded for webhook:', webhook.name);
                results.push({
                    webhook_id: webhook.id,
                    webhook_name: webhook.name,
                    status: 'rate_limited',
                    next_allowed: rateLimitCheck.nextAllowed
                });
                continue;
            }

            // Send webhook notification
            const result = await sendWebhookNotification(webhook, notificationPayload, hook);
            results.push(result);

            if (result.status === 'success') {
                successCount++;
                updateWebhookStats(webhook.id, true);
            } else {
                failureCount++;
                updateWebhookStats(webhook.id, false);
                
                // Queue for retry if configured
                if (webhook.retry.enabled && result.retry_eligible) {
                    queueWebhookRetry(webhook, notificationPayload, hook, result.attempt || 1);
                }
            }
        }

        // Add email tags
        if (payload.email) {
            Email.addTag(`webhook-notifications:${successCount}`);
            if (failureCount > 0) {
                Email.addTag(`webhook-failures:${failureCount}`);
            }
        }

        console.log(`Webhook notifications completed. Success: ${successCount}, Failures: ${failureCount}`);

        return {
            success: true,
            result: {
                action: 'notifications_sent',
                hook: hook,
                total_webhooks: relevantWebhooks.length,
                successful: successCount,
                failed: failureCount,
                results: results
            }
        };

    } catch (error) {
        console.error('Webhook notifier error:', error.message);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Get webhook configuration
 */
function getWebhookConfig() {
    const defaultConfig = {
        enabled: true,
        global_rate_limit: {
            max_per_minute: 60,
            max_per_hour: 1000
        },
        default_timeout: 30,
        default_retry: {
            enabled: true,
            max_attempts: 3,
            backoff_multiplier: 2,
            initial_delay: 1000
        },
        webhooks: [
            {
                id: 'slack-notifications',
                name: 'Slack Notifications',
                enabled: true,
                url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                hooks: ['email.received', 'email.processed'],
                conditions: {
                    email_status: ['new', 'processed'],
                    min_spam_score: null,
                    max_spam_score: 50,
                    from_domains: [],
                    exclude_domains: ['noreply.com'],
                    subject_contains: [],
                    subject_excludes: ['test', 'internal']
                },
                payload_template: 'slack',
                timeout: 10,
                retry: {
                    enabled: true,
                    max_attempts: 3,
                    backoff_multiplier: 2,
                    initial_delay: 1000
                },
                rate_limit: {
                    max_per_minute: 10,
                    max_per_hour: 100
                }
            },
            {
                id: 'discord-alerts',
                name: 'Discord Alerts',
                enabled: true,
                url: 'https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                hooks: ['email.received'],
                conditions: {
                    email_status: ['new'],
                    min_spam_score: 70,
                    max_spam_score: null,
                    from_domains: [],
                    exclude_domains: [],
                    subject_contains: [],
                    subject_excludes: []
                },
                payload_template: 'discord',
                timeout: 15,
                retry: {
                    enabled: true,
                    max_attempts: 2,
                    backoff_multiplier: 1.5,
                    initial_delay: 500
                },
                rate_limit: {
                    max_per_minute: 5,
                    max_per_hour: 50
                }
            },
            {
                id: 'custom-api',
                name: 'Custom API Integration',
                enabled: false,
                url: 'https://api.example.com/webhooks/email',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer YOUR_API_TOKEN',
                    'X-API-Version': 'v1'
                },
                hooks: ['email.received', 'email.processed', 'email.sent'],
                conditions: {
                    email_status: [],
                    min_spam_score: null,
                    max_spam_score: null,
                    from_domains: [],
                    exclude_domains: [],
                    subject_contains: [],
                    subject_excludes: []
                },
                payload_template: 'custom',
                timeout: 30,
                retry: {
                    enabled: true,
                    max_attempts: 5,
                    backoff_multiplier: 2,
                    initial_delay: 2000
                },
                rate_limit: {
                    max_per_minute: 30,
                    max_per_hour: 500
                }
            }
        ]
    };

    // Try to get user configuration from storage
    try {
        const userConfig = Storage.get('webhook_config');
        if (userConfig) {
            const parsed = JSON.parse(userConfig);
            return { ...defaultConfig, ...parsed };
        }
    } catch (error) {
        console.warn('Could not load webhook configuration, using defaults');
    }

    return defaultConfig;
}

/**
 * Prepare notification payload
 */
function preparePayload(hook, payload, config) {
    const basePayload = {
        event: hook,
        timestamp: new Date().toISOString(),
        tenant_id: payload.tenant_id || 'unknown',
        user_id: payload.user_id || 'unknown'
    };

    // Add email data if available
    if (payload.email) {
        basePayload.email = {
            id: payload.email.id,
            message_id: payload.email.message_id,
            subject: payload.email.subject,
            from: payload.email.from,
            to: payload.email.to,
            received_at: payload.email.received_at,
            status: payload.email.status,
            tags: payload.email.tags || [],
            has_attachments: (payload.email.attachments || []).length > 0,
            attachment_count: (payload.email.attachments || []).length,
            body_preview: truncateText(payload.email.body || '', 200)
        };

        // Add spam score if available
        const spamScoreTag = (payload.email.tags || []).find(tag => tag.startsWith('spam-score:'));
        if (spamScoreTag) {
            basePayload.email.spam_score = parseInt(spamScoreTag.split(':')[1]) || 0;
        }
    }

    return basePayload;
}

/**
 * Evaluate webhook conditions
 */
function evaluateWebhookConditions(webhook, payload) {
    const conditions = webhook.conditions;
    const email = payload.email;

    if (!email) {
        return true; // No email data to evaluate
    }

    // Check email status
    if (conditions.email_status && conditions.email_status.length > 0) {
        if (!conditions.email_status.includes(email.status)) {
            return false;
        }
    }

    // Check spam score range
    const spamScore = getSpamScore(email);
    if (conditions.min_spam_score !== null && spamScore < conditions.min_spam_score) {
        return false;
    }
    if (conditions.max_spam_score !== null && spamScore > conditions.max_spam_score) {
        return false;
    }

    // Check from domains
    const fromDomain = (email.from.address || '').split('@')[1] || '';
    if (conditions.from_domains && conditions.from_domains.length > 0) {
        if (!conditions.from_domains.some(domain => fromDomain.includes(domain))) {
            return false;
        }
    }

    // Check exclude domains
    if (conditions.exclude_domains && conditions.exclude_domains.length > 0) {
        if (conditions.exclude_domains.some(domain => fromDomain.includes(domain))) {
            return false;
        }
    }

    // Check subject contains
    const subject = (email.subject || '').toLowerCase();
    if (conditions.subject_contains && conditions.subject_contains.length > 0) {
        if (!conditions.subject_contains.some(keyword => subject.includes(keyword.toLowerCase()))) {
            return false;
        }
    }

    // Check subject excludes
    if (conditions.subject_excludes && conditions.subject_excludes.length > 0) {
        if (conditions.subject_excludes.some(keyword => subject.includes(keyword.toLowerCase()))) {
            return false;
        }
    }

    return true;
}

/**
 * Check webhook rate limiting
 */
function checkWebhookRateLimit(webhook) {
    const now = new Date();
    const key = `webhook_rate_limit_${webhook.id}`;
    
    try {
        const rateLimitData = Storage.get(key);
        if (!rateLimitData) {
            return { allowed: true };
        }
        
        const data = JSON.parse(rateLimitData);
        
        // Check minute limit
        const minuteStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 
                                   now.getHours(), now.getMinutes());
        if (data.minute_start === minuteStart.toISOString() && 
            data.minute_count >= webhook.rate_limit.max_per_minute) {
            return { 
                allowed: false, 
                reason: 'Minute limit exceeded',
                nextAllowed: new Date(minuteStart.getTime() + 60000).toISOString()
            };
        }
        
        // Check hour limit
        const hourStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours());
        if (data.hour_start === hourStart.toISOString() && 
            data.hour_count >= webhook.rate_limit.max_per_hour) {
            return { 
                allowed: false, 
                reason: 'Hour limit exceeded',
                nextAllowed: new Date(hourStart.getTime() + 3600000).toISOString()
            };
        }
        
    } catch (error) {
        console.warn('Error checking webhook rate limit:', error.message);
    }
    
    return { allowed: true };
}

/**
 * Send webhook notification
 */
async function sendWebhookNotification(webhook, payload, hook) {
    const startTime = Date.now();
    
    try {
        // Prepare webhook-specific payload
        const webhookPayload = formatPayloadForWebhook(webhook, payload, hook);
        
        // Send HTTP request
        const response = await Http.post(webhook.url, webhookPayload, {
            headers: webhook.headers,
            timeout: (webhook.timeout || 30) * 1000
        });
        
        const duration = Date.now() - startTime;
        
        // Update rate limiting
        updateWebhookRateLimit(webhook.id);
        
        console.log(`Webhook sent successfully to ${webhook.name} (${duration}ms)`);
        
        return {
            webhook_id: webhook.id,
            webhook_name: webhook.name,
            status: 'success',
            response_status: response.status,
            duration_ms: duration,
            attempt: 1
        };
        
    } catch (error) {
        const duration = Date.now() - startTime;
        
        console.error(`Webhook failed for ${webhook.name}:`, error.message);
        
        return {
            webhook_id: webhook.id,
            webhook_name: webhook.name,
            status: 'failed',
            error: error.message,
            duration_ms: duration,
            retry_eligible: isRetryEligibleError(error),
            attempt: 1
        };
    }
}

/**
 * Format payload for specific webhook template
 */
function formatPayloadForWebhook(webhook, payload, hook) {
    switch (webhook.payload_template) {
        case 'slack':
            return formatSlackPayload(payload, hook);
        case 'discord':
            return formatDiscordPayload(payload, hook);
        case 'custom':
            return formatCustomPayload(payload, hook);
        default:
            return payload; // Return raw payload
    }
}

/**
 * Format payload for Slack
 */
function formatSlackPayload(payload, hook) {
    const email = payload.email;
    
    if (!email) {
        return {
            text: `Email event: ${hook}`,
            channel: '#email-notifications'
        };
    }
    
    const color = getSlackColor(email);
    const spamScore = getSpamScore(email);
    
    return {
        channel: '#email-notifications',
        username: 'Pat Email Monitor',
        icon_emoji: ':email:',
        attachments: [
            {
                color: color,
                title: `New Email: ${email.subject || '(No Subject)'}`,
                title_link: `https://pat.email/emails/${email.id}`,
                fields: [
                    {
                        title: 'From',
                        value: `${email.from.name || email.from.address}`,
                        short: true
                    },
                    {
                        title: 'Status',
                        value: email.status || 'unknown',
                        short: true
                    },
                    {
                        title: 'Spam Score',
                        value: spamScore.toString(),
                        short: true
                    },
                    {
                        title: 'Received',
                        value: formatDateTime(email.received_at),
                        short: true
                    }
                ],
                footer: 'Pat Email Platform',
                ts: Math.floor(new Date(payload.timestamp).getTime() / 1000)
            }
        ]
    };
}

/**
 * Format payload for Discord
 */
function formatDiscordPayload(payload, hook) {
    const email = payload.email;
    
    if (!email) {
        return {
            content: `Email event: ${hook}`,
            embeds: []
        };
    }
    
    const color = getDiscordColor(email);
    const spamScore = getSpamScore(email);
    
    return {
        embeds: [
            {
                title: 'New Email Received',
                description: email.subject || '(No Subject)',
                color: color,
                fields: [
                    {
                        name: 'From',
                        value: `${email.from.name || email.from.address}`,
                        inline: true
                    },
                    {
                        name: 'Status',
                        value: email.status || 'unknown',
                        inline: true
                    },
                    {
                        name: 'Spam Score',
                        value: spamScore.toString(),
                        inline: true
                    }
                ],
                footer: {
                    text: 'Pat Email Platform'
                },
                timestamp: payload.timestamp
            }
        ]
    };
}

/**
 * Format payload for custom API
 */
function formatCustomPayload(payload, hook) {
    return {
        event_type: hook,
        data: payload,
        api_version: '1.0',
        source: 'pat-email-platform'
    };
}

/**
 * Get spam score from email tags
 */
function getSpamScore(email) {
    if (!email.tags) return 0;
    
    const spamScoreTag = email.tags.find(tag => tag.startsWith('spam-score:'));
    if (spamScoreTag) {
        return parseInt(spamScoreTag.split(':')[1]) || 0;
    }
    
    return 0;
}

/**
 * Get Slack color based on email status/spam score
 */
function getSlackColor(email) {
    const spamScore = getSpamScore(email);
    
    if (spamScore >= 70) return 'danger';  // Red
    if (spamScore >= 50) return 'warning'; // Yellow
    if (email.status === 'quarantined') return 'danger';
    return 'good'; // Green
}

/**
 * Get Discord color based on email status/spam score
 */
function getDiscordColor(email) {
    const spamScore = getSpamScore(email);
    
    if (spamScore >= 70) return 0xFF0000;  // Red
    if (spamScore >= 50) return 0xFFA500;  // Orange
    if (email.status === 'quarantined') return 0xFF0000;
    return 0x00FF00; // Green
}

/**
 * Update webhook rate limiting data
 */
function updateWebhookRateLimit(webhookId) {
    const now = new Date();
    const key = `webhook_rate_limit_${webhookId}`;
    
    try {
        let data = { minute_count: 0, hour_count: 0 };
        
        const existing = Storage.get(key);
        if (existing) {
            data = JSON.parse(existing);
        }
        
        const minuteStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 
                                   now.getHours(), now.getMinutes());
        const hourStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours());
        
        // Reset counts if new period
        if (data.minute_start !== minuteStart.toISOString()) {
            data.minute_count = 0;
            data.minute_start = minuteStart.toISOString();
        }
        
        if (data.hour_start !== hourStart.toISOString()) {
            data.hour_count = 0;
            data.hour_start = hourStart.toISOString();
        }
        
        data.minute_count++;
        data.hour_count++;
        data.last_sent = now.toISOString();
        
        Storage.set(key, JSON.stringify(data));
    } catch (error) {
        console.warn('Error updating webhook rate limit:', error.message);
    }
}

/**
 * Update webhook statistics
 */
function updateWebhookStats(webhookId, success) {
    const key = `webhook_stats_${webhookId}`;
    
    try {
        let stats = { 
            total_sent: 0, 
            successful: 0, 
            failed: 0, 
            last_success: null, 
            last_failure: null 
        };
        
        const existing = Storage.get(key);
        if (existing) {
            stats = JSON.parse(existing);
        }
        
        stats.total_sent++;
        if (success) {
            stats.successful++;
            stats.last_success = new Date().toISOString();
        } else {
            stats.failed++;
            stats.last_failure = new Date().toISOString();
        }
        
        Storage.set(key, JSON.stringify(stats));
    } catch (error) {
        console.warn('Error updating webhook stats:', error.message);
    }
}

/**
 * Queue webhook for retry
 */
function queueWebhookRetry(webhook, payload, hook, attempt) {
    const retryKey = `webhook_retry_${webhook.id}_${Date.now()}`;
    const delay = webhook.retry.initial_delay * Math.pow(webhook.retry.backoff_multiplier, attempt - 1);
    
    const retryData = {
        webhook_id: webhook.id,
        payload: payload,
        hook: hook,
        attempt: attempt + 1,
        scheduled_for: new Date(Date.now() + delay).toISOString(),
        max_attempts: webhook.retry.max_attempts
    };
    
    try {
        Storage.set(retryKey, JSON.stringify(retryData));
        console.log(`Queued webhook retry for ${webhook.name}, attempt ${attempt + 1} in ${delay}ms`);
    } catch (error) {
        console.error('Failed to queue webhook retry:', error.message);
    }
}

/**
 * Check if error is eligible for retry
 */
function isRetryEligibleError(error) {
    // Retry on network errors, timeouts, and 5xx status codes
    const retryableErrors = [
        'timeout',
        'network',
        'connection',
        'server error',
        '5'
    ];
    
    const errorMessage = error.message.toLowerCase();
    return retryableErrors.some(keyword => errorMessage.includes(keyword));
}

/**
 * Utility functions
 */
function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

function formatDateTime(dateString) {
    try {
        return new Date(dateString).toLocaleString();
    } catch {
        return dateString || 'Unknown';
    }
}

// Export for testing (if in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        main,
        preparePayload,
        evaluateWebhookConditions,
        formatSlackPayload,
        formatDiscordPayload,
        getSpamScore
    };
}