/**
 * Link Validator Plugin
 * 
 * Validates and analyzes all links in incoming emails.
 * Checks for malicious URLs, phishing attempts, and broken links.
 * 
 * @author Pat Team
 * @version 1.0.0
 * @permissions email:read, email:write, http:request
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

        console.log('Starting link validation for email:', email.id);

        // Extract all URLs from email body
        const urls = extractUrls(email.body || '');
        
        if (urls.length === 0) {
            console.log('No URLs found in email');
            Email.addTag('no-links');
            return {
                success: true,
                result: {
                    total_links: 0,
                    safe_links: 0,
                    suspicious_links: 0,
                    malicious_links: 0,
                    broken_links: 0
                }
            };
        }

        console.log('Found', urls.length, 'URLs to validate');

        // Validate each URL
        const results = [];
        let safeCount = 0;
        let suspiciousCount = 0;
        let maliciousCount = 0;
        let brokenCount = 0;

        for (const url of urls) {
            const validation = validateUrl(url);
            results.push(validation);

            switch (validation.status) {
                case 'safe':
                    safeCount++;
                    break;
                case 'suspicious':
                    suspiciousCount++;
                    break;
                case 'malicious':
                    maliciousCount++;
                    break;
                case 'broken':
                    brokenCount++;
                    break;
            }
        }

        // Add tags based on findings
        Email.addTag(`links-total:${urls.length}`);
        Email.addTag(`links-safe:${safeCount}`);
        
        if (suspiciousCount > 0) {
            Email.addTag(`links-suspicious:${suspiciousCount}`);
            Email.addTag('suspicious-links');
        }
        
        if (maliciousCount > 0) {
            Email.addTag(`links-malicious:${maliciousCount}`);
            Email.addTag('malicious-links');
            // Set email status to quarantine if malicious links found
            Email.setStatus('quarantined');
        }
        
        if (brokenCount > 0) {
            Email.addTag(`links-broken:${brokenCount}`);
        }

        // Calculate overall safety score
        const safetyScore = calculateSafetyScore(safeCount, suspiciousCount, maliciousCount, brokenCount);
        Email.addTag(`link-safety-score:${safetyScore}`);

        console.log('Link validation completed. Safety score:', safetyScore);

        return {
            success: true,
            result: {
                total_links: urls.length,
                safe_links: safeCount,
                suspicious_links: suspiciousCount,
                malicious_links: maliciousCount,
                broken_links: brokenCount,
                safety_score: safetyScore,
                details: results
            }
        };

    } catch (error) {
        console.error('Link validator error:', error.message);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Extract all URLs from email body
 */
function extractUrls(body) {
    const urls = [];
    
    // URL regex pattern (simplified)
    const urlRegex = /https?:\/\/[^\s<>"'\[\]{}|\\^`]+/gi;
    const matches = body.match(urlRegex) || [];
    
    // Also check for HTML links
    const htmlLinkRegex = /<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let htmlMatch;
    while ((htmlMatch = htmlLinkRegex.exec(body)) !== null) {
        matches.push(htmlMatch[1]);
    }
    
    // Clean and deduplicate URLs
    const seen = new Set();
    matches.forEach(url => {
        const cleanUrl = cleanUrl(url);
        if (cleanUrl && !seen.has(cleanUrl)) {
            seen.add(cleanUrl);
            urls.push(cleanUrl);
        }
    });
    
    return urls;
}

/**
 * Clean and normalize URL
 */
function cleanUrl(url) {
    try {
        // Remove trailing punctuation
        url = url.replace(/[.,;!?]+$/, '');
        
        // Ensure protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        
        // Validate URL format
        const urlObj = new URL(url);
        return urlObj.href;
    } catch {
        return null;
    }
}

/**
 * Validate a single URL
 */
function validateUrl(url) {
    const result = {
        url: url,
        status: 'safe',
        issues: [],
        redirect_chain: [],
        final_url: url,
        response_time: 0
    };

    try {
        const urlObj = new URL(url);
        
        // Check domain reputation
        const domainCheck = checkDomainReputation(urlObj.hostname);
        if (domainCheck.status !== 'safe') {
            result.status = domainCheck.status;
            result.issues.push(...domainCheck.issues);
        }
        
        // Check URL patterns
        const patternCheck = checkUrlPatterns(url);
        if (patternCheck.status !== 'safe') {
            result.status = getWorseStatus(result.status, patternCheck.status);
            result.issues.push(...patternCheck.issues);
        }
        
        // Check URL shorteners
        const shortenerCheck = checkUrlShorteners(urlObj.hostname);
        if (shortenerCheck.isSuspicious) {
            result.status = getWorseStatus(result.status, 'suspicious');
            result.issues.push('URL shortener detected');
        }
        
        // Try to resolve URL (simplified)
        const resolutionCheck = checkUrlResolution(url);
        if (resolutionCheck.status !== 'safe') {
            result.status = getWorseStatus(result.status, resolutionCheck.status);
            result.issues.push(...resolutionCheck.issues);
            result.redirect_chain = resolutionCheck.redirects || [];
            result.final_url = resolutionCheck.finalUrl || url;
        }
        
    } catch (error) {
        result.status = 'broken';
        result.issues.push('Invalid URL format');
    }
    
    return result;
}

/**
 * Check domain reputation
 */
function checkDomainReputation(hostname) {
    const result = {
        status: 'safe',
        issues: []
    };
    
    // Known malicious domains (simplified list)
    const maliciousDomains = [
        'phishing-site.com',
        'malware-host.net',
        'suspicious-domain.org',
        'fake-bank.com'
    ];
    
    // Suspicious TLDs
    const suspiciousTlds = [
        '.tk', '.ml', '.ga', '.cf', '.su', '.cc'
    ];
    
    // Check against known bad domains
    if (maliciousDomains.some(domain => hostname.includes(domain))) {
        result.status = 'malicious';
        result.issues.push('Known malicious domain');
        return result;
    }
    
    // Check suspicious TLDs
    if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
        result.status = 'suspicious';
        result.issues.push('Suspicious top-level domain');
    }
    
    // Check for homograph attacks (simplified)
    if (containsSuspiciousCharacters(hostname)) {
        result.status = 'suspicious';
        result.issues.push('Suspicious characters in domain');
    }
    
    // Check for typosquatting (simplified)
    const typoCheck = checkTyposquatting(hostname);
    if (typoCheck.isSuspicious) {
        result.status = 'suspicious';
        result.issues.push('Possible typosquatting');
    }
    
    return result;
}

/**
 * Check URL patterns for suspicious content
 */
function checkUrlPatterns(url) {
    const result = {
        status: 'safe',
        issues: []
    };
    
    const lowerUrl = url.toLowerCase();
    
    // Suspicious patterns
    const suspiciousPatterns = [
        /[a-z0-9]{20,}/, // Long random strings
        /login.*redirect/,
        /secure.*update/,
        /verify.*account/,
        /suspended.*account/,
        /click.*here.*now/,
        /urgent.*action/
    ];
    
    // Malicious patterns
    const maliciousPatterns = [
        /phishing/,
        /malware/,
        /trojan/,
        /virus/,
        /exploit/,
        /payload/
    ];
    
    // Check malicious patterns first
    for (const pattern of maliciousPatterns) {
        if (pattern.test(lowerUrl)) {
            result.status = 'malicious';
            result.issues.push('Malicious pattern detected');
            return result;
        }
    }
    
    // Check suspicious patterns
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(lowerUrl)) {
            result.status = 'suspicious';
            result.issues.push('Suspicious pattern detected');
            break;
        }
    }
    
    // Check for IP addresses instead of domains
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
        result.status = 'suspicious';
        result.issues.push('IP address instead of domain');
    }
    
    // Check for unusual ports
    if (/:\d{4,5}/.test(url)) {
        const port = url.match(/:(\d{4,5})/)[1];
        if (port !== '8080' && port !== '8443') {
            result.status = 'suspicious';
            result.issues.push('Unusual port number');
        }
    }
    
    return result;
}

/**
 * Check if domain uses URL shorteners
 */
function checkUrlShorteners(hostname) {
    const shorteners = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'short.link', 'rb.gy', 'cutt.ly'
    ];
    
    return {
        isSuspicious: shorteners.some(shortener => hostname.includes(shortener))
    };
}

/**
 * Check URL resolution (simplified mock)
 */
function checkUrlResolution(url) {
    // In a real implementation, this would make HTTP requests
    // For this demo, we'll simulate the check
    
    const result = {
        status: 'safe',
        issues: [],
        redirects: [],
        finalUrl: url
    };
    
    // Simulate redirect detection
    if (url.includes('redirect') || url.includes('r.') || url.includes('goto')) {
        result.redirects.push(url);
        result.finalUrl = url + '/final-destination';
        result.issues.push('URL contains redirects');
        result.status = 'suspicious';
    }
    
    // Simulate broken link detection
    if (url.includes('broken') || url.includes('404') || url.includes('notfound')) {
        result.status = 'broken';
        result.issues.push('URL appears to be broken');
    }
    
    return result;
}

/**
 * Check for suspicious characters (homograph attacks)
 */
function containsSuspiciousCharacters(hostname) {
    // Check for mix of scripts (simplified)
    const hasLatin = /[a-zA-Z]/.test(hostname);
    const hasCyrillic = /[а-яё]/i.test(hostname);
    const hasGreek = /[α-ω]/i.test(hostname);
    
    // If multiple scripts are mixed, it's suspicious
    const scriptCount = [hasLatin, hasCyrillic, hasGreek].filter(Boolean).length;
    return scriptCount > 1;
}

/**
 * Check for typosquatting (simplified)
 */
function checkTyposquatting(hostname) {
    const popularDomains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'ebay.com', 'netflix.com'
    ];
    
    // Calculate edit distance to popular domains
    for (const domain of popularDomains) {
        const distance = levenshteinDistance(hostname, domain);
        if (distance > 0 && distance <= 2) {
            return { isSuspicious: true, similarTo: domain };
        }
    }
    
    return { isSuspicious: false };
}

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(str1, str2) {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
    
    for (let i = 0; i <= str1.length; i++) {
        matrix[0][i] = i;
    }
    
    for (let j = 0; j <= str2.length; j++) {
        matrix[j][0] = j;
    }
    
    for (let j = 1; j <= str2.length; j++) {
        for (let i = 1; i <= str1.length; i++) {
            const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[j][i] = Math.min(
                matrix[j][i - 1] + 1,
                matrix[j - 1][i] + 1,
                matrix[j - 1][i - 1] + indicator
            );
        }
    }
    
    return matrix[str2.length][str1.length];
}

/**
 * Calculate overall safety score
 */
function calculateSafetyScore(safe, suspicious, malicious, broken) {
    const total = safe + suspicious + malicious + broken;
    if (total === 0) return 100;
    
    const score = (safe * 100 + suspicious * 50 + malicious * 0 + broken * 25) / total;
    return Math.round(score);
}

/**
 * Get worse status between two statuses
 */
function getWorseStatus(status1, status2) {
    const severity = { 'safe': 0, 'broken': 1, 'suspicious': 2, 'malicious': 3 };
    return severity[status1] >= severity[status2] ? status1 : status2;
}

// Export for testing (if in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        main,
        extractUrls,
        validateUrl,
        checkDomainReputation,
        checkUrlPatterns,
        calculateSafetyScore
    };
}