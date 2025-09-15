/**
 * Spam Scorer Plugin
 * 
 * Analyzes incoming emails and assigns a spam score based on various criteria.
 * This plugin demonstrates email analysis, scoring algorithms, and tagging.
 * 
 * @author Pat Team
 * @version 1.0.0
 * @permissions email:read, email:write
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

        console.log('Starting spam analysis for email:', email.id);

        // Calculate spam score
        const score = calculateSpamScore(email);
        const isSpam = score >= 70; // Threshold for spam

        console.log('Spam score calculated:', score);

        // Add spam score as metadata
        Email.addTag(`spam-score:${score}`);

        // Mark as spam if score is high
        if (isSpam) {
            Email.addTag('spam');
            Email.setStatus('spam');
            console.log('Email marked as spam with score:', score);
        } else {
            Email.addTag('ham');
            console.log('Email marked as ham with score:', score);
        }

        return {
            success: true,
            result: {
                spam_score: score,
                is_spam: isSpam,
                classification: isSpam ? 'spam' : 'ham'
            }
        };

    } catch (error) {
        console.error('Spam scorer error:', error.message);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Calculate spam score based on multiple criteria
 */
function calculateSpamScore(email) {
    let score = 0;

    // Subject line analysis
    score += analyzeSubject(email.subject || '');
    
    // From address analysis
    score += analyzeFromAddress(email.from || {});
    
    // Body content analysis
    score += analyzeBody(email.body || '');
    
    // Headers analysis
    score += analyzeHeaders(email.headers || {});
    
    // Attachments analysis
    score += analyzeAttachments(email.attachments || []);

    return Math.min(score, 100); // Cap at 100
}

/**
 * Analyze subject line for spam indicators
 */
function analyzeSubject(subject) {
    let score = 0;
    const lowerSubject = subject.toLowerCase();

    // Common spam phrases
    const spamPhrases = [
        'urgent', 'limited time', 'act now', 'click here', 'free money',
        'guaranteed', 'no obligation', 'risk free', 'special promotion',
        'winner', 'congratulations', 'you have won', 'claim now',
        'viagra', 'cialis', 'pharmacy', 'weight loss', 'diet pills'
    ];

    spamPhrases.forEach(phrase => {
        if (lowerSubject.includes(phrase)) {
            score += 15;
        }
    });

    // Excessive punctuation
    const exclamations = (subject.match(/!/g) || []).length;
    if (exclamations > 2) {
        score += Math.min(exclamations * 5, 20);
    }

    // All caps
    if (subject === subject.toUpperCase() && subject.length > 10) {
        score += 25;
    }

    // Numbers and currency symbols
    if (/\$\d+/.test(subject)) {
        score += 10;
    }

    // Suspicious patterns
    if (/RE:|FW:/i.test(subject) && subject.length < 20) {
        score += 5; // Short RE/FW might be suspicious
    }

    return score;
}

/**
 * Analyze from address for spam indicators
 */
function analyzeFromAddress(from) {
    let score = 0;

    if (!from.address) {
        return 0;
    }

    const email = from.address.toLowerCase();
    const domain = email.split('@')[1] || '';

    // Suspicious domains
    const suspiciousDomains = [
        'tempmail.com', '10minutemail.com', 'guerrillamail.com',
        'yopmail.com', 'mailinator.com'
    ];

    if (suspiciousDomains.some(d => domain.includes(d))) {
        score += 30;
    }

    // Random-looking email addresses
    const localPart = email.split('@')[0] || '';
    if (localPart.length > 15 && /^[a-z0-9]{10,}$/.test(localPart)) {
        score += 15; // Long random string
    }

    // No display name for promotional content
    if (!from.name || from.name.trim() === '') {
        score += 5;
    }

    // Suspicious display names
    if (from.name) {
        const lowerName = from.name.toLowerCase();
        if (lowerName.includes('admin') || lowerName.includes('support') || 
            lowerName.includes('service')) {
            score += 10;
        }
    }

    return score;
}

/**
 * Analyze email body for spam indicators
 */
function analyzeBody(body) {
    let score = 0;
    const lowerBody = body.toLowerCase();

    // Spam keywords
    const spamKeywords = [
        'click here', 'buy now', 'order now', 'visit our website',
        'limited time offer', 'act fast', 'don\'t miss out',
        'make money fast', 'work from home', 'easy money',
        'no experience required', 'opportunity', 'investment',
        'casino', 'lottery', 'gambling', 'bitcoin', 'cryptocurrency'
    ];

    spamKeywords.forEach(keyword => {
        const regex = new RegExp(keyword, 'gi');
        const matches = (body.match(regex) || []).length;
        score += matches * 5;
    });

    // URL analysis
    const urlMatches = body.match(/https?:\/\/[^\s]+/gi) || [];
    if (urlMatches.length > 5) {
        score += Math.min(urlMatches.length * 3, 25);
    }

    // Suspicious URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
    urlMatches.forEach(url => {
        if (shorteners.some(s => url.includes(s))) {
            score += 10;
        }
    });

    // Excessive capitalization
    const capsRatio = (body.match(/[A-Z]/g) || []).length / body.length;
    if (capsRatio > 0.3 && body.length > 100) {
        score += 20;
    }

    // HTML analysis (if body contains HTML)
    if (body.includes('<') && body.includes('>')) {
        // Hidden text (color manipulation)
        if (/style="[^"]*color\s*:\s*white/i.test(body) ||
            /style="[^"]*font-size\s*:\s*0/i.test(body)) {
            score += 25;
        }

        // Excessive images
        const imgTags = (body.match(/<img/gi) || []).length;
        if (imgTags > 10) {
            score += 15;
        }
    }

    // Urgency indicators
    const urgencyWords = ['urgent', 'asap', 'immediately', 'expire', 'deadline'];
    urgencyWords.forEach(word => {
        if (lowerBody.includes(word)) {
            score += 8;
        }
    });

    return score;
}

/**
 * Analyze email headers for spam indicators
 */
function analyzeHeaders(headers) {
    let score = 0;

    // Missing standard headers
    if (!headers['message-id']) {
        score += 10;
    }

    if (!headers['date']) {
        score += 5;
    }

    // Suspicious received headers
    const received = headers['received'] || '';
    if (Array.isArray(received)) {
        // Multiple received headers might indicate forwarding
        if (received.length > 8) {
            score += 10;
        }
    }

    // Check for bulk mail indicators
    if (headers['precedence'] === 'bulk' || 
        headers['x-precedence'] === 'bulk') {
        score += 15;
    }

    // Suspicious user agents
    const userAgent = headers['user-agent'] || headers['x-mailer'] || '';
    const suspiciousAgents = ['bulk', 'mass', 'spam', 'bot'];
    if (suspiciousAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
        score += 20;
    }

    // Missing or suspicious return path
    const returnPath = headers['return-path'] || '';
    if (!returnPath || returnPath.includes('bounce') || returnPath.includes('noreply')) {
        score += 5;
    }

    return score;
}

/**
 * Analyze attachments for spam indicators
 */
function analyzeAttachments(attachments) {
    let score = 0;

    if (attachments.length === 0) {
        return 0;
    }

    // Suspicious file types
    const suspiciousTypes = [
        '.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js',
        '.jar', '.com', '.zip', '.rar'
    ];

    attachments.forEach(attachment => {
        const filename = (attachment.filename || '').toLowerCase();
        
        // Check for suspicious extensions
        if (suspiciousTypes.some(type => filename.endsWith(type))) {
            score += 25;
        }

        // Double extensions (e.g., .pdf.exe)
        const dots = (filename.match(/\./g) || []).length;
        if (dots > 1) {
            score += 15;
        }

        // Very long filenames
        if (filename.length > 50) {
            score += 10;
        }

        // Random-looking filenames
        if (/^[a-z0-9]{10,}\.[a-z]+$/.test(filename)) {
            score += 10;
        }
    });

    // Too many attachments
    if (attachments.length > 5) {
        score += Math.min(attachments.length * 5, 25);
    }

    return score;
}

// Export for testing (if in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        main,
        calculateSpamScore,
        analyzeSubject,
        analyzeFromAddress,
        analyzeBody,
        analyzeHeaders,
        analyzeAttachments
    };
}