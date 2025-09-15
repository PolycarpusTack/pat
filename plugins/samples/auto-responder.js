/**
 * Auto-Responder Plugin
 * 
 * Automatically sends responses to emails based on configurable rules.
 * Supports templates, conditions, and scheduling.
 * 
 * @author Pat Team
 * @version 1.0.0
 * @permissions email:read, email:write, storage:read, storage:write
 * @hooks email.received
 */

function main(hook, payload) {
    try {
        if (hook !== 'email.received') {
            return { success: false, error: 'Unsupported hook' };
        }

        const email = payload.email;
        if (!email) {
            return { success: false, error: 'No email provided' };
        }

        console.log('Processing auto-responder for email:', email.id);

        // Get auto-responder configuration
        const config = getAutoResponderConfig();
        
        if (!config.enabled) {
            console.log('Auto-responder is disabled');
            return { success: true, result: { action: 'disabled' } };
        }

        // Check if we should respond to this email
        const shouldRespond = evaluateResponseConditions(email, config);
        
        if (!shouldRespond.respond) {
            console.log('Email does not meet response conditions:', shouldRespond.reason);
            Email.addTag('auto-responder:skipped');
            return { 
                success: true, 
                result: { 
                    action: 'skipped',
                    reason: shouldRespond.reason 
                } 
            };
        }

        // Check rate limiting
        const rateLimitCheck = checkRateLimit(email.from.address, config);
        if (!rateLimitCheck.allowed) {
            console.log('Rate limit exceeded for sender:', email.from.address);
            Email.addTag('auto-responder:rate-limited');
            return { 
                success: true, 
                result: { 
                    action: 'rate_limited',
                    next_allowed: rateLimitCheck.nextAllowed 
                } 
            };
        }

        // Select appropriate template
        const template = selectTemplate(email, config);
        if (!template) {
            console.log('No suitable template found');
            Email.addTag('auto-responder:no-template');
            return { 
                success: true, 
                result: { 
                    action: 'no_template' 
                } 
            };
        }

        // Generate response
        const response = generateResponse(email, template, config);
        
        // Send response (simulated)
        const sent = sendResponse(response, email);
        
        if (sent.success) {
            // Update rate limiting
            updateRateLimit(email.from.address);
            
            // Add tags
            Email.addTag('auto-responder:sent');
            Email.addTag(`auto-responder:template:${template.id}`);
            
            console.log('Auto-response sent successfully using template:', template.id);
            
            return {
                success: true,
                result: {
                    action: 'sent',
                    template_id: template.id,
                    response_id: sent.messageId,
                    subject: response.subject
                }
            };
        } else {
            console.error('Failed to send auto-response:', sent.error);
            Email.addTag('auto-responder:failed');
            
            return {
                success: false,
                error: `Failed to send response: ${sent.error}`
            };
        }

    } catch (error) {
        console.error('Auto-responder error:', error.message);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Get auto-responder configuration
 */
function getAutoResponderConfig() {
    // In a real implementation, this would come from Storage API
    // For demo purposes, we'll return a default configuration
    
    const defaultConfig = {
        enabled: true,
        global_enabled: true,
        rate_limit: {
            max_per_sender_per_day: 1,
            max_per_sender_per_hour: 1,
            cooldown_minutes: 60
        },
        conditions: {
            respond_to_bounce: false,
            respond_to_auto_reply: false,
            respond_to_no_reply: false,
            min_subject_length: 3,
            required_keywords: [],
            excluded_keywords: ['unsubscribe', 'spam', 'test'],
            sender_whitelist: [],
            sender_blacklist: ['noreply@', 'no-reply@', 'bounce@'],
            domain_whitelist: [],
            domain_blacklist: []
        },
        templates: [
            {
                id: 'default',
                name: 'Default Auto-Reply',
                priority: 1,
                conditions: {},
                subject: 'Re: {{original_subject}}',
                body: `Thank you for your email. This is an automatic response to let you know that we have received your message.

We will review your email and respond as soon as possible, typically within 24 hours during business days.

If this is urgent, please contact us directly at [phone number].

Best regards,
The Team

---
Original message subject: {{original_subject}}
Received: {{received_date}}`,
                html_body: null,
                delay_minutes: 0
            },
            {
                id: 'support',
                name: 'Support Request Auto-Reply',
                priority: 10,
                conditions: {
                    subject_contains: ['help', 'support', 'issue', 'problem', 'bug'],
                    keywords: ['support', 'help']
                },
                subject: 'Support Request Received: {{original_subject}}',
                body: `Hello {{sender_name}},

Thank you for contacting our support team. We have received your support request and assigned it ticket number #{{ticket_number}}.

Our support team will review your request and respond within:
- Critical issues: 2 hours
- Standard issues: 24 hours
- General inquiries: 48 hours

You can track the status of your ticket at: https://support.example.com/ticket/{{ticket_number}}

Best regards,
Support Team`,
                html_body: null,
                delay_minutes: 0
            },
            {
                id: 'sales',
                name: 'Sales Inquiry Auto-Reply',
                priority: 10,
                conditions: {
                    subject_contains: ['price', 'quote', 'sales', 'purchase', 'buy'],
                    keywords: ['sales', 'pricing', 'quote']
                },
                subject: 'Thank you for your interest - {{original_subject}}',
                body: `Dear {{sender_name}},

Thank you for your interest in our products/services. We have received your sales inquiry.

A member of our sales team will contact you within 24 hours to discuss your requirements and provide you with the information you need.

In the meantime, you may find these resources helpful:
- Product catalog: https://example.com/catalog
- Pricing guide: https://example.com/pricing
- Case studies: https://example.com/cases

Best regards,
Sales Team`,
                html_body: null,
                delay_minutes: 5
            }
        ],
        schedule: {
            enabled: false,
            business_hours_only: false,
            timezone: 'UTC',
            business_hours: {
                monday: { start: '09:00', end: '17:00' },
                tuesday: { start: '09:00', end: '17:00' },
                wednesday: { start: '09:00', end: '17:00' },
                thursday: { start: '09:00', end: '17:00' },
                friday: { start: '09:00', end: '17:00' },
                saturday: null,
                sunday: null
            }
        }
    };

    // Try to get user configuration from storage
    try {
        const userConfig = Storage.get('auto_responder_config');
        if (userConfig) {
            return { ...defaultConfig, ...JSON.parse(userConfig) };
        }
    } catch (error) {
        console.warn('Could not load user configuration, using defaults');
    }

    return defaultConfig;
}

/**
 * Evaluate if we should respond to this email
 */
function evaluateResponseConditions(email, config) {
    const conditions = config.conditions;
    
    // Check if globally enabled
    if (!config.global_enabled) {
        return { respond: false, reason: 'Auto-responder globally disabled' };
    }

    // Check for auto-reply indicators
    if (!conditions.respond_to_auto_reply) {
        const autoReplyHeaders = [
            'auto-submitted',
            'x-auto-response-suppress',
            'x-autorespond',
            'precedence'
        ];
        
        for (const header of autoReplyHeaders) {
            if (email.headers && email.headers[header]) {
                return { respond: false, reason: 'Email appears to be auto-generated' };
            }
        }
    }

    // Check for bounce emails
    if (!conditions.respond_to_bounce) {
        const bounceIndicators = [
            'mailer-daemon',
            'postmaster',
            'delivery',
            'bounce',
            'return'
        ];
        
        const fromAddress = (email.from.address || '').toLowerCase();
        if (bounceIndicators.some(indicator => fromAddress.includes(indicator))) {
            return { respond: false, reason: 'Email appears to be a bounce message' };
        }
    }

    // Check for no-reply emails
    if (!conditions.respond_to_no_reply) {
        const fromAddress = (email.from.address || '').toLowerCase();
        if (fromAddress.includes('noreply') || fromAddress.includes('no-reply')) {
            return { respond: false, reason: 'Email from no-reply address' };
        }
    }

    // Check sender blacklist
    const fromAddress = (email.from.address || '').toLowerCase();
    for (const blocked of conditions.sender_blacklist) {
        if (fromAddress.includes(blocked.toLowerCase())) {
            return { respond: false, reason: `Sender matches blacklist: ${blocked}` };
        }
    }

    // Check domain blacklist
    const domain = fromAddress.split('@')[1] || '';
    for (const blockedDomain of conditions.domain_blacklist) {
        if (domain.includes(blockedDomain.toLowerCase())) {
            return { respond: false, reason: `Domain matches blacklist: ${blockedDomain}` };
        }
    }

    // Check sender whitelist (if specified)
    if (conditions.sender_whitelist.length > 0) {
        const isWhitelisted = conditions.sender_whitelist.some(allowed => 
            fromAddress.includes(allowed.toLowerCase())
        );
        if (!isWhitelisted) {
            return { respond: false, reason: 'Sender not in whitelist' };
        }
    }

    // Check domain whitelist (if specified)
    if (conditions.domain_whitelist.length > 0) {
        const isDomainWhitelisted = conditions.domain_whitelist.some(allowedDomain => 
            domain.includes(allowedDomain.toLowerCase())
        );
        if (!isDomainWhitelisted) {
            return { respond: false, reason: 'Domain not in whitelist' };
        }
    }

    // Check subject length
    const subject = email.subject || '';
    if (subject.length < conditions.min_subject_length) {
        return { respond: false, reason: 'Subject too short' };
    }

    // Check excluded keywords
    const emailText = (subject + ' ' + (email.body || '')).toLowerCase();
    for (const keyword of conditions.excluded_keywords) {
        if (emailText.includes(keyword.toLowerCase())) {
            return { respond: false, reason: `Contains excluded keyword: ${keyword}` };
        }
    }

    // Check required keywords (if specified)
    if (conditions.required_keywords.length > 0) {
        const hasRequiredKeyword = conditions.required_keywords.some(keyword =>
            emailText.includes(keyword.toLowerCase())
        );
        if (!hasRequiredKeyword) {
            return { respond: false, reason: 'Does not contain required keywords' };
        }
    }

    return { respond: true, reason: 'All conditions met' };
}

/**
 * Check rate limiting for sender
 */
function checkRateLimit(senderAddress, config) {
    const rateLimit = config.rate_limit;
    const now = new Date();
    const key = `rate_limit_${senderAddress}`;
    
    try {
        const rateLimitData = Storage.get(key);
        if (!rateLimitData) {
            return { allowed: true };
        }
        
        const data = JSON.parse(rateLimitData);
        const lastSent = new Date(data.last_sent);
        
        // Check cooldown period
        const cooldownExpired = (now - lastSent) >= (rateLimit.cooldown_minutes * 60 * 1000);
        if (!cooldownExpired) {
            const nextAllowed = new Date(lastSent.getTime() + (rateLimit.cooldown_minutes * 60 * 1000));
            return { 
                allowed: false, 
                reason: 'Cooldown period',
                nextAllowed: nextAllowed.toISOString()
            };
        }
        
        // Check daily limit
        const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        if (lastSent >= todayStart && data.daily_count >= rateLimit.max_per_sender_per_day) {
            return { 
                allowed: false, 
                reason: 'Daily limit exceeded',
                nextAllowed: new Date(todayStart.getTime() + 24 * 60 * 60 * 1000).toISOString()
            };
        }
        
        // Check hourly limit
        const hourStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours());
        if (lastSent >= hourStart && data.hourly_count >= rateLimit.max_per_sender_per_hour) {
            return { 
                allowed: false, 
                reason: 'Hourly limit exceeded',
                nextAllowed: new Date(hourStart.getTime() + 60 * 60 * 1000).toISOString()
            };
        }
        
    } catch (error) {
        console.warn('Error checking rate limit:', error.message);
    }
    
    return { allowed: true };
}

/**
 * Update rate limiting data
 */
function updateRateLimit(senderAddress) {
    const now = new Date();
    const key = `rate_limit_${senderAddress}`;
    
    try {
        let data = { daily_count: 0, hourly_count: 0 };
        
        const existing = Storage.get(key);
        if (existing) {
            data = JSON.parse(existing);
            const lastSent = new Date(data.last_sent);
            
            // Reset daily count if new day
            const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            if (lastSent < todayStart) {
                data.daily_count = 0;
            }
            
            // Reset hourly count if new hour
            const hourStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours());
            if (lastSent < hourStart) {
                data.hourly_count = 0;
            }
        }
        
        data.daily_count++;
        data.hourly_count++;
        data.last_sent = now.toISOString();
        
        Storage.set(key, JSON.stringify(data));
    } catch (error) {
        console.warn('Error updating rate limit:', error.message);
    }
}

/**
 * Select appropriate template based on email content
 */
function selectTemplate(email, config) {
    const templates = config.templates.sort((a, b) => b.priority - a.priority);
    
    for (const template of templates) {
        if (templateMatches(email, template)) {
            return template;
        }
    }
    
    return null;
}

/**
 * Check if template conditions match the email
 */
function templateMatches(email, template) {
    if (!template.conditions) {
        return true; // No conditions means always match
    }
    
    const conditions = template.conditions;
    const subject = (email.subject || '').toLowerCase();
    const body = (email.body || '').toLowerCase();
    const emailText = subject + ' ' + body;
    
    // Check subject_contains conditions
    if (conditions.subject_contains) {
        const matches = conditions.subject_contains.some(keyword =>
            subject.includes(keyword.toLowerCase())
        );
        if (!matches) return false;
    }
    
    // Check keywords conditions
    if (conditions.keywords) {
        const matches = conditions.keywords.some(keyword =>
            emailText.includes(keyword.toLowerCase())
        );
        if (!matches) return false;
    }
    
    // Check sender conditions
    if (conditions.from_contains) {
        const fromAddress = (email.from.address || '').toLowerCase();
        const matches = conditions.from_contains.some(keyword =>
            fromAddress.includes(keyword.toLowerCase())
        );
        if (!matches) return false;
    }
    
    return true;
}

/**
 * Generate response email from template
 */
function generateResponse(email, template, config) {
    const variables = createTemplateVariables(email);
    
    const response = {
        to: email.from.address,
        subject: processTemplate(template.subject, variables),
        body: processTemplate(template.body, variables),
        html_body: template.html_body ? processTemplate(template.html_body, variables) : null,
        in_reply_to: email.message_id,
        references: email.message_id
    };
    
    return response;
}

/**
 * Create variables for template processing
 */
function createTemplateVariables(email) {
    const now = new Date();
    
    return {
        original_subject: email.subject || '(No Subject)',
        sender_name: email.from.name || email.from.address || 'Unknown',
        sender_email: email.from.address || 'unknown',
        received_date: now.toLocaleDateString(),
        received_time: now.toLocaleTimeString(),
        ticket_number: generateTicketNumber(),
        current_date: now.toLocaleDateString(),
        current_time: now.toLocaleTimeString()
    };
}

/**
 * Process template with variables
 */
function processTemplate(template, variables) {
    let result = template;
    
    for (const [key, value] of Object.entries(variables)) {
        const placeholder = `{{${key}}}`;
        result = result.replace(new RegExp(placeholder, 'g'), value);
    }
    
    return result;
}

/**
 * Generate ticket number
 */
function generateTicketNumber() {
    const now = new Date();
    const timestamp = now.getTime().toString().slice(-6);
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    return `${timestamp}${random}`;
}

/**
 * Send response email (simulated)
 */
function sendResponse(response, originalEmail) {
    // In a real implementation, this would use the Email API to send
    console.log('Sending auto-response:', {
        to: response.to,
        subject: response.subject,
        in_reply_to: response.in_reply_to
    });
    
    // Simulate successful send
    return {
        success: true,
        messageId: `auto-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };
}

// Export for testing (if in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        main,
        evaluateResponseConditions,
        checkRateLimit,
        selectTemplate,
        generateResponse,
        processTemplate
    };
}