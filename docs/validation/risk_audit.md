# MailHog Risk Assessment & Security Audit
**Generated**: 2025-06-11
**Severity Levels**: ❗ Critical | ⚠️ High | ⚡ Medium | ℹ️ Low

## Executive Summary

MailHog has **3 critical** and **5 high** security/technical risks requiring immediate attention. The codebase shows its age (2017) with abandoned dependencies and missing modern security practices.

## Critical Risks (Immediate Action Required)

### 1. ❗ CVE-2020-27813: gorilla/websocket DoS Vulnerability
- **Location**: WebSocket implementation for real-time updates
- **Impact**: Remote attacker can crash service via integer overflow
- **CVSS Score**: 7.5 (High)
- **Current Version**: 2017-03-19 (vulnerable)
- **Fix**: Update to gorilla/websocket v1.5.1+
- **Effort**: 2 hours
- **Code Changes**: Update import, test WebSocket functionality

### 2. ❗ Abandoned MongoDB Driver (mgo.v2)
- **Location**: `storage/mongodb.go`
- **Impact**: No security updates since 2018, potential data corruption
- **Risk**: Unpatched vulnerabilities, compatibility issues
- **Current**: `gopkg.in/mgo.v2` (abandoned)
- **Fix**: Migrate to `go.mongodb.org/mongo-driver`
- **Effort**: 2-3 days
- **Breaking Changes**: API differences require code refactoring

### 3. ❗ Outdated Cryptography Library
- **Location**: `golang.org/x/crypto` (2016 version)
- **Impact**: Missing 7+ years of security patches
- **Usage**: BCrypt password hashing for HTTP auth
- **Fix**: Update to latest version
- **Effort**: 1 hour
- **Validation**: Test authentication still works

## High-Risk Issues

### 4. ⚠️ No Input Validation on SMTP
- **Location**: `smtp/session.go:acceptMessage()`
- **Impact**: Potential injection attacks, resource exhaustion
- **Evidence**: No email validation, no rate limiting
- **Fix**: Add input validation and rate limiting
- **Effort**: 1 day

### 5. ⚠️ Unbounded Memory Growth
- **Location**: `storage/memory.go`
- **Impact**: Out of memory crashes under load
- **Evidence**: No message limit in in-memory storage
- **Fix**: Implement circular buffer or message limit
- **Effort**: 4 hours

### 6. ⚠️ No CORS Validation
- **Location**: `api/v1/api.go`, `api/v2/api.go`
- **Impact**: Cross-origin attacks on API
- **Current**: Accepts any origin when configured
- **Fix**: Validate CORS origins against allowlist
- **Effort**: 2 hours

### 7. ⚠️ Insecure Default Configuration
- **Location**: Configuration defaults
- **Issues**:
  - No authentication by default
  - Wide-open network binding (0.0.0.0)
  - No TLS support
- **Fix**: Secure defaults, clear security documentation
- **Effort**: 1 day

### 8. ⚠️ Path Traversal in Maildir Storage
- **Location**: `storage/maildir.go`
- **Risk**: Potential file system access outside maildir
- **Evidence**: No path sanitization on message IDs
- **Fix**: Validate and sanitize file paths
- **Effort**: 2 hours

## Medium-Risk Issues

### 9. ⚡ No Dependency Scanning
- **Impact**: Unknown vulnerabilities in dependencies
- **Current**: Manual updates only
- **Fix**: Add automated scanning in CI/CD
- **Tools**: Trivy, Snyk, or GitHub Dependabot
- **Effort**: 2 hours

### 10. ⚡ Weak BCrypt Cost Factor
- **Location**: `main.go:66` - hardcoded cost 4
- **Impact**: Faster brute force attacks
- **Current**: Cost factor 4 (too low)
- **Recommended**: Cost factor 12+
- **Fix**: Make configurable, increase default
- **Effort**: 1 hour

### 11. ⚡ No Security Headers
- **Location**: HTTP responses
- **Missing Headers**:
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
- **Fix**: Add security headers middleware
- **Effort**: 2 hours

### 12. ⚡ Verbose Error Messages
- **Location**: Throughout codebase
- **Risk**: Information disclosure
- **Evidence**: Stack traces exposed to clients
- **Fix**: Sanitize error messages in production
- **Effort**: 4 hours

## Low-Risk Issues

### 13. ℹ️ No Audit Logging
- **Impact**: Cannot track security events
- **Fix**: Add structured logging for security events
- **Effort**: 1 day

### 14. ℹ️ Missing Security Documentation
- **Impact**: Users unaware of security implications
- **Fix**: Create security best practices guide
- **Effort**: 4 hours

### 15. ℹ️ No Container Security Scanning
- **Location**: Dockerfile
- **Risk**: Vulnerable base images
- **Fix**: Add container scanning to CI/CD
- **Effort**: 2 hours

## Technical Debt Impact on Security

### Code Quality Issues
1. **No Error Handling**: Panics can crash service
2. **Race Conditions**: Concurrent map access without locks
3. **Resource Leaks**: Goroutines not properly closed
4. **No Context Cancellation**: Can't stop long operations

### Missing Modern Practices
1. **No Structured Logging**: Hard to detect attacks
2. **No Metrics/Monitoring**: Can't detect anomalies
3. **No Health Checks**: Service state unknown
4. **No Graceful Shutdown**: Data loss possible

## Recommended Security Improvements

### Phase 1: Critical Fixes (Week 1)
```bash
# Update vulnerable dependencies
go get -u github.com/gorilla/websocket@latest
go get -u golang.org/x/crypto@latest

# Replace abandoned MongoDB driver
go get go.mongodb.org/mongo-driver/mongo
```

### Phase 2: High-Risk Fixes (Week 2-3)
1. Add input validation layer
2. Implement rate limiting
3. Add memory bounds
4. Sanitize file paths
5. Validate CORS origins

### Phase 3: Security Hardening (Week 4)
1. Add security headers
2. Implement audit logging
3. Create security documentation
4. Set up dependency scanning
5. Add container scanning

## Security Testing Checklist

### Authentication Testing
```bash
# Test without auth
curl -i http://localhost:8025/api/v1/messages

# Test with invalid auth
curl -i -u wrong:wrong http://localhost:8025/api/v1/messages

# Test BCrypt cost factor
time ./MailHog bcrypt testpassword
```

### Input Validation Testing
```bash
# Test email injection
echo -e "MAIL FROM:<test@example.com>\r\nRCPT TO:<../../etc/passwd>" | nc localhost 1025

# Test header injection
echo -e "Subject: Test\r\nBcc: attacker@evil.com\r\n\r\nBody" | nc localhost 1025

# Test large message
dd if=/dev/random bs=1M count=100 | nc localhost 1025
```

### API Security Testing
```bash
# Test CORS
curl -H "Origin: http://evil.com" http://localhost:8025/api/v1/messages

# Test XXE
curl -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' http://localhost:8025/api/v1/messages
```

## Compliance Considerations

### GDPR/Privacy
- Email content may contain PII
- No data retention policy
- No data encryption at rest
- No audit trail for access

### Development Best Practices
- Using as intended (development only)
- Not for production use
- Clear documentation needed
- Security warnings required

## Risk Mitigation Priority

1. **Update Dependencies** (1 day) - Fixes 3 critical issues
2. **Add Input Validation** (2 days) - Prevents injection attacks
3. **Implement Resource Limits** (1 day) - Prevents DoS
4. **Add Security Headers** (4 hours) - Basic hardening
5. **Create Security Docs** (4 hours) - User awareness

## Conclusion

MailHog requires immediate security updates to remain viable. The core architecture is sound, but the implementation shows its age. With 1-2 weeks of focused security work, most risks can be mitigated while maintaining backward compatibility.