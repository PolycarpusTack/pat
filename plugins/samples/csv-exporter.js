/**
 * CSV Exporter Plugin
 * 
 * Exports email data to CSV format with customizable fields and filtering.
 * Supports scheduled exports and multiple output formats.
 * 
 * @author Pat Team
 * @version 1.0.0
 * @permissions email:read, storage:read, storage:write
 * @hooks workflow.start, user.login
 */

function main(hook, payload) {
    try {
        console.log('CSV exporter triggered for hook:', hook);

        // Handle different hooks
        switch (hook) {
            case 'workflow.start':
                return handleWorkflowExport(payload);
            case 'user.login':
                return handleScheduledExports(payload);
            default:
                return { success: false, error: 'Unsupported hook' };
        }

    } catch (error) {
        console.error('CSV exporter error:', error.message);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Handle workflow-triggered export
 */
function handleWorkflowExport(payload) {
    const workflowConfig = payload.workflow_config;
    
    if (!workflowConfig || workflowConfig.type !== 'csv_export') {
        return { success: true, result: { action: 'not_csv_export' } };
    }

    console.log('Processing CSV export workflow');

    // Get export configuration
    const exportConfig = workflowConfig.csv_export || getDefaultExportConfig();
    
    // Apply filters
    const emails = getFilteredEmails(exportConfig.filters);
    
    if (emails.length === 0) {
        console.log('No emails match the export criteria');
        return {
            success: true,
            result: {
                action: 'no_emails',
                total_emails: 0,
                exported_emails: 0
            }
        };
    }

    // Generate CSV
    const csvData = generateCSV(emails, exportConfig);
    
    // Save export
    const exportResult = saveExport(csvData, exportConfig, emails.length);
    
    console.log(`CSV export completed: ${emails.length} emails exported`);
    
    return {
        success: true,
        result: {
            action: 'export_completed',
            total_emails: emails.length,
            exported_emails: emails.length,
            export_id: exportResult.export_id,
            file_size: csvData.length,
            download_url: exportResult.download_url
        }
    };
}

/**
 * Handle scheduled exports
 */
function handleScheduledExports(payload) {
    console.log('Checking for scheduled exports');

    // Get scheduled export configurations
    const scheduledExports = getScheduledExports();
    
    if (scheduledExports.length === 0) {
        return { success: true, result: { action: 'no_scheduled_exports' } };
    }

    const now = new Date();
    let processedCount = 0;

    for (const exportConfig of scheduledExports) {
        if (shouldRunScheduledExport(exportConfig, now)) {
            console.log('Running scheduled export:', exportConfig.name);
            
            // Apply filters
            const emails = getFilteredEmails(exportConfig.filters);
            
            if (emails.length > 0) {
                // Generate CSV
                const csvData = generateCSV(emails, exportConfig);
                
                // Save export
                const exportResult = saveExport(csvData, exportConfig, emails.length);
                
                // Update last run time
                updateScheduledExportLastRun(exportConfig.id, now);
                
                processedCount++;
                console.log(`Scheduled export completed: ${emails.length} emails`);
            }
        }
    }

    return {
        success: true,
        result: {
            action: 'scheduled_exports_processed',
            processed_exports: processedCount
        }
    };
}

/**
 * Get default export configuration
 */
function getDefaultExportConfig() {
    return {
        name: 'Email Export',
        fields: [
            'id', 'message_id', 'subject', 'from_address', 'from_name',
            'to_addresses', 'received_at', 'status', 'spam_score', 'tags'
        ],
        filters: {
            date_range: {
                start: null,
                end: null
            },
            status: [],
            spam_score_min: null,
            spam_score_max: null,
            from_domains: [],
            exclude_domains: [],
            tags: [],
            exclude_tags: [],
            has_attachments: null
        },
        format: {
            delimiter: ',',
            quote_char: '"',
            escape_char: '\\',
            include_header: true,
            date_format: 'YYYY-MM-DD HH:mm:ss'
        },
        limits: {
            max_records: 10000,
            max_file_size_mb: 50
        }
    };
}

/**
 * Get filtered emails based on criteria
 */
function getFilteredEmails(filters) {
    // In a real implementation, this would query the database
    // For demo purposes, we'll return simulated data
    
    const sampleEmails = generateSampleEmails(100);
    let filteredEmails = [...sampleEmails];

    // Apply date range filter
    if (filters.date_range && filters.date_range.start) {
        const startDate = new Date(filters.date_range.start);
        filteredEmails = filteredEmails.filter(email => 
            new Date(email.received_at) >= startDate
        );
    }

    if (filters.date_range && filters.date_range.end) {
        const endDate = new Date(filters.date_range.end);
        filteredEmails = filteredEmails.filter(email => 
            new Date(email.received_at) <= endDate
        );
    }

    // Apply status filter
    if (filters.status && filters.status.length > 0) {
        filteredEmails = filteredEmails.filter(email => 
            filters.status.includes(email.status)
        );
    }

    // Apply spam score filters
    if (filters.spam_score_min !== null) {
        filteredEmails = filteredEmails.filter(email => 
            getEmailSpamScore(email) >= filters.spam_score_min
        );
    }

    if (filters.spam_score_max !== null) {
        filteredEmails = filteredEmails.filter(email => 
            getEmailSpamScore(email) <= filters.spam_score_max
        );
    }

    // Apply domain filters
    if (filters.from_domains && filters.from_domains.length > 0) {
        filteredEmails = filteredEmails.filter(email => {
            const domain = email.from_address.split('@')[1] || '';
            return filters.from_domains.some(d => domain.includes(d));
        });
    }

    if (filters.exclude_domains && filters.exclude_domains.length > 0) {
        filteredEmails = filteredEmails.filter(email => {
            const domain = email.from_address.split('@')[1] || '';
            return !filters.exclude_domains.some(d => domain.includes(d));
        });
    }

    // Apply tag filters
    if (filters.tags && filters.tags.length > 0) {
        filteredEmails = filteredEmails.filter(email => 
            filters.tags.some(tag => email.tags.includes(tag))
        );
    }

    if (filters.exclude_tags && filters.exclude_tags.length > 0) {
        filteredEmails = filteredEmails.filter(email => 
            !filters.exclude_tags.some(tag => email.tags.includes(tag))
        );
    }

    // Apply attachment filter
    if (filters.has_attachments !== null) {
        filteredEmails = filteredEmails.filter(email => 
            email.has_attachments === filters.has_attachments
        );
    }

    return filteredEmails;
}

/**
 * Generate CSV data from emails
 */
function generateCSV(emails, config) {
    const fields = config.fields || [];
    const format = config.format || {};
    const delimiter = format.delimiter || ',';
    const quoteChar = format.quote_char || '"';
    const escapeChar = format.escape_char || '\\';
    const includeHeader = format.include_header !== false;

    let csvLines = [];

    // Add header if requested
    if (includeHeader) {
        const header = fields.map(field => formatCSVField(getFieldDisplayName(field), quoteChar, escapeChar));
        csvLines.push(header.join(delimiter));
    }

    // Add data rows
    for (const email of emails) {
        const row = fields.map(field => {
            const value = getEmailFieldValue(email, field, format);
            return formatCSVField(value, quoteChar, escapeChar);
        });
        csvLines.push(row.join(delimiter));
    }

    return csvLines.join('\n');
}

/**
 * Get display name for field
 */
function getFieldDisplayName(field) {
    const displayNames = {
        'id': 'Email ID',
        'message_id': 'Message ID',
        'subject': 'Subject',
        'from_address': 'From Address',
        'from_name': 'From Name',
        'to_addresses': 'To Addresses',
        'cc_addresses': 'CC Addresses',
        'bcc_addresses': 'BCC Addresses',
        'received_at': 'Received At',
        'processed_at': 'Processed At',
        'status': 'Status',
        'spam_score': 'Spam Score',
        'tags': 'Tags',
        'has_attachments': 'Has Attachments',
        'attachment_count': 'Attachment Count',
        'body_preview': 'Body Preview',
        'body_length': 'Body Length'
    };

    return displayNames[field] || field;
}

/**
 * Get email field value
 */
function getEmailFieldValue(email, field, format) {
    switch (field) {
        case 'id':
            return email.id || '';
        case 'message_id':
            return email.message_id || '';
        case 'subject':
            return email.subject || '';
        case 'from_address':
            return email.from_address || '';
        case 'from_name':
            return email.from_name || '';
        case 'to_addresses':
            return Array.isArray(email.to_addresses) ? email.to_addresses.join('; ') : email.to_addresses || '';
        case 'cc_addresses':
            return Array.isArray(email.cc_addresses) ? email.cc_addresses.join('; ') : email.cc_addresses || '';
        case 'bcc_addresses':
            return Array.isArray(email.bcc_addresses) ? email.bcc_addresses.join('; ') : email.bcc_addresses || '';
        case 'received_at':
            return formatDate(email.received_at, format.date_format);
        case 'processed_at':
            return formatDate(email.processed_at, format.date_format);
        case 'status':
            return email.status || '';
        case 'spam_score':
            return getEmailSpamScore(email).toString();
        case 'tags':
            return Array.isArray(email.tags) ? email.tags.join('; ') : email.tags || '';
        case 'has_attachments':
            return email.has_attachments ? 'Yes' : 'No';
        case 'attachment_count':
            return (email.attachment_count || 0).toString();
        case 'body_preview':
            return truncateText(email.body || '', 200);
        case 'body_length':
            return (email.body || '').length.toString();
        default:
            return '';
    }
}

/**
 * Format CSV field value
 */
function formatCSVField(value, quoteChar, escapeChar) {
    if (value === null || value === undefined) {
        value = '';
    }
    
    const stringValue = String(value);
    
    // Check if value needs quoting
    const needsQuoting = stringValue.includes(',') || 
                        stringValue.includes('\n') || 
                        stringValue.includes('\r') || 
                        stringValue.includes(quoteChar);

    if (needsQuoting) {
        // Escape quote characters
        const escapedValue = stringValue.replace(new RegExp(quoteChar, 'g'), escapeChar + quoteChar);
        return quoteChar + escapedValue + quoteChar;
    }

    return stringValue;
}

/**
 * Format date according to specified format
 */
function formatDate(dateString, dateFormat) {
    if (!dateString) return '';
    
    try {
        const date = new Date(dateString);
        
        switch (dateFormat) {
            case 'YYYY-MM-DD':
                return date.toISOString().split('T')[0];
            case 'YYYY-MM-DD HH:mm:ss':
                return date.toISOString().replace('T', ' ').split('.')[0];
            case 'MM/DD/YYYY':
                return date.toLocaleDateString('en-US');
            case 'DD/MM/YYYY':
                return date.toLocaleDateString('en-GB');
            default:
                return date.toISOString();
        }
    } catch {
        return dateString;
    }
}

/**
 * Save export data
 */
function saveExport(csvData, config, emailCount) {
    const exportId = generateExportId();
    const filename = generateFilename(config.name || 'email_export', 'csv');
    
    // Save to storage (in real implementation, this would save to S3 or similar)
    const exportRecord = {
        id: exportId,
        filename: filename,
        config: config,
        email_count: emailCount,
        file_size: csvData.length,
        created_at: new Date().toISOString(),
        data: csvData // In real implementation, this would be a file path/URL
    };

    try {
        // Save export metadata
        const exportsKey = 'csv_exports';
        let exports = [];
        const existingExports = Storage.get(exportsKey);
        if (existingExports) {
            exports = JSON.parse(existingExports);
        }
        
        exports.push({
            id: exportId,
            filename: filename,
            config_name: config.name,
            email_count: emailCount,
            file_size: csvData.length,
            created_at: exportRecord.created_at
        });

        // Keep only last 50 exports
        exports = exports.slice(-50);
        Storage.set(exportsKey, JSON.stringify(exports));

        // Save export data
        Storage.set(`csv_export_${exportId}`, JSON.stringify(exportRecord));

        console.log('Export saved successfully:', exportId);

        return {
            export_id: exportId,
            filename: filename,
            download_url: `/exports/${exportId}/download` // Simulated URL
        };

    } catch (error) {
        console.error('Failed to save export:', error.message);
        throw new Error('Failed to save export data');
    }
}

/**
 * Get scheduled exports
 */
function getScheduledExports() {
    try {
        const scheduledExportsData = Storage.get('scheduled_csv_exports');
        if (scheduledExportsData) {
            return JSON.parse(scheduledExportsData);
        }
    } catch (error) {
        console.warn('Could not load scheduled exports');
    }

    // Return default scheduled exports
    return [
        {
            id: 'daily-summary',
            name: 'Daily Email Summary',
            enabled: true,
            schedule: {
                type: 'daily',
                time: '09:00',
                timezone: 'UTC'
            },
            filters: {
                date_range: {
                    start: 'yesterday',
                    end: 'yesterday'
                },
                status: ['processed'],
                spam_score_min: null,
                spam_score_max: null
            },
            fields: ['id', 'subject', 'from_address', 'received_at', 'status', 'spam_score'],
            last_run: null
        },
        {
            id: 'weekly-spam-report',
            name: 'Weekly Spam Report',
            enabled: true,
            schedule: {
                type: 'weekly',
                day: 'monday',
                time: '08:00',
                timezone: 'UTC'
            },
            filters: {
                date_range: {
                    start: 'last_week',
                    end: 'last_week'
                },
                spam_score_min: 50,
                spam_score_max: null
            },
            fields: ['id', 'subject', 'from_address', 'received_at', 'spam_score', 'tags'],
            last_run: null
        }
    ];
}

/**
 * Check if scheduled export should run
 */
function shouldRunScheduledExport(exportConfig, now) {
    if (!exportConfig.enabled) return false;

    const schedule = exportConfig.schedule;
    const lastRun = exportConfig.last_run ? new Date(exportConfig.last_run) : null;

    switch (schedule.type) {
        case 'daily':
            if (!lastRun) return true;
            const daysSinceLastRun = Math.floor((now - lastRun) / (24 * 60 * 60 * 1000));
            return daysSinceLastRun >= 1 && now.getHours() >= parseInt(schedule.time.split(':')[0]);

        case 'weekly':
            if (!lastRun) return true;
            const weeksSinceLastRun = Math.floor((now - lastRun) / (7 * 24 * 60 * 60 * 1000));
            const targetDay = getDayNumber(schedule.day);
            return weeksSinceLastRun >= 1 && now.getDay() === targetDay;

        case 'monthly':
            if (!lastRun) return true;
            const monthsSinceLastRun = (now.getFullYear() - lastRun.getFullYear()) * 12 + 
                                      (now.getMonth() - lastRun.getMonth());
            return monthsSinceLastRun >= 1 && now.getDate() === (schedule.day_of_month || 1);

        default:
            return false;
    }
}

/**
 * Update scheduled export last run time
 */
function updateScheduledExportLastRun(exportId, timestamp) {
    try {
        const scheduledExportsData = Storage.get('scheduled_csv_exports');
        if (scheduledExportsData) {
            const exports = JSON.parse(scheduledExportsData);
            const exportIndex = exports.findIndex(exp => exp.id === exportId);
            
            if (exportIndex !== -1) {
                exports[exportIndex].last_run = timestamp.toISOString();
                Storage.set('scheduled_csv_exports', JSON.stringify(exports));
            }
        }
    } catch (error) {
        console.warn('Could not update scheduled export last run time');
    }
}

/**
 * Utility functions
 */
function generateSampleEmails(count) {
    const emails = [];
    const domains = ['example.com', 'test.org', 'sample.net', 'demo.co'];
    const statuses = ['new', 'processed', 'quarantined', 'deleted'];
    
    for (let i = 0; i < count; i++) {
        emails.push({
            id: `email_${i + 1}`,
            message_id: `msg_${Date.now()}_${i}`,
            subject: `Test Email ${i + 1}`,
            from_address: `user${i}@${domains[i % domains.length]}`,
            from_name: `User ${i + 1}`,
            to_addresses: ['recipient@example.com'],
            received_at: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
            status: statuses[i % statuses.length],
            tags: [`tag${i % 3}`, 'processed'],
            has_attachments: i % 4 === 0,
            attachment_count: i % 4 === 0 ? 1 : 0,
            body: `This is the body of test email ${i + 1}.`
        });
    }
    
    return emails;
}

function getEmailSpamScore(email) {
    if (email.tags) {
        const spamScoreTag = email.tags.find(tag => tag.startsWith('spam-score:'));
        if (spamScoreTag) {
            return parseInt(spamScoreTag.split(':')[1]) || 0;
        }
    }
    return Math.floor(Math.random() * 100); // Random score for demo
}

function generateExportId() {
    return 'export_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function generateFilename(baseName, extension) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    return `${baseName}_${timestamp}.${extension}`;
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

function getDayNumber(dayName) {
    const days = {
        'sunday': 0, 'monday': 1, 'tuesday': 2, 'wednesday': 3,
        'thursday': 4, 'friday': 5, 'saturday': 6
    };
    return days[dayName.toLowerCase()] || 0;
}

// Export for testing (if in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        main,
        generateCSV,
        getFilteredEmails,
        formatCSVField,
        shouldRunScheduledExport
    };
}