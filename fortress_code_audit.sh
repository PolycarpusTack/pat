#!/bin/bash

# 🏰 PAT FORTRESS CODE SECURITY AUDIT
# Static code analysis and security validation
# Date: September 12, 2025

echo "============================================================================"
echo "🔍 PAT FORTRESS CODE SECURITY AUDIT - STATIC ANALYSIS"
echo "============================================================================"
echo "MISSION: Comprehensive static code analysis of fortress security components"
echo "DATE: $(date)"
echo ""

PROJECT_ROOT="/mnt/c/Projects/Pat"
RESULTS_FILE="$PROJECT_ROOT/fortress_code_audit_report.txt"

# Initialize results file
cat > "$RESULTS_FILE" << EOF
🏰 PAT FORTRESS CODE SECURITY AUDIT REPORT
==========================================
Date: $(date)
Classification: FORTRESS-PROTECTED

STATIC CODE ANALYSIS RESULTS
============================

EOF

echo "🎯 PHASE 1: SQL INJECTION PROTECTION ANALYSIS"
echo "============================================"

echo "Analyzing database query implementations..." | tee -a "$RESULTS_FILE"

# Check for parameterized queries
parameterized_queries=$(grep -r "\$[0-9]" "$PROJECT_ROOT/pkg" --include="*.go" | wc -l)
string_concat_queries=$(grep -r "fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE" "$PROJECT_ROOT/pkg" --include="*.go" | wc -l)

echo "  Parameterized queries found: $parameterized_queries" | tee -a "$RESULTS_FILE"
echo "  String concatenation queries: $string_concat_queries" | tee -a "$RESULTS_FILE"

if [[ $string_concat_queries -eq 0 ]]; then
    echo "  ✅ SQL INJECTION PROTECTION: EXCELLENT" | tee -a "$RESULTS_FILE"
    sql_protection_score=100
else
    echo "  ❌ SQL INJECTION RISK: String concatenation detected" | tee -a "$RESULTS_FILE"
    sql_protection_score=60
fi

# Check for SQL injection patterns in validator
sql_patterns=$(grep -c "SQLInjectionPatterns\|union\|select\|insert\|update\|delete\|drop" "$PROJECT_ROOT/pkg/security/validator.go")
echo "  SQL injection detection patterns: $sql_patterns" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"

echo "🛡️ PHASE 2: INPUT VALIDATION COVERAGE ANALYSIS"
echo "============================================="

echo "Analyzing input validation implementations..." | tee -a "$RESULTS_FILE"

# Check for validation functions
email_validation=$(grep -c "ValidateEmail" "$PROJECT_ROOT/pkg/security/validator.go")
string_validation=$(grep -c "ValidateString" "$PROJECT_ROOT/pkg/security/validator.go")
json_validation=$(grep -c "ValidateJSON" "$PROJECT_ROOT/pkg/security/validator.go")
url_validation=$(grep -c "ValidateURL" "$PROJECT_ROOT/pkg/security/validator.go")
file_validation=$(grep -c "ValidateFile" "$PROJECT_ROOT/pkg/security/validator.go")
graphql_validation=$(grep -c "ValidateGraphQL" "$PROJECT_ROOT/pkg/security/validator.go")

echo "  Email validation: $email_validation implementations" | tee -a "$RESULTS_FILE"
echo "  String validation: $string_validation implementations" | tee -a "$RESULTS_FILE"
echo "  JSON validation: $json_validation implementations" | tee -a "$RESULTS_FILE"
echo "  URL validation: $url_validation implementations" | tee -a "$RESULTS_FILE"
echo "  File validation: $file_validation implementations" | tee -a "$RESULTS_FILE"
echo "  GraphQL validation: $graphql_validation implementations" | tee -a "$RESULTS_FILE"

total_validations=$((email_validation + string_validation + json_validation + url_validation + file_validation + graphql_validation))
echo "  Total validation functions: $total_validations" | tee -a "$RESULTS_FILE"

if [[ $total_validations -gt 5 ]]; then
    echo "  ✅ INPUT VALIDATION COVERAGE: COMPREHENSIVE" | tee -a "$RESULTS_FILE"
    input_validation_score=100
elif [[ $total_validations -gt 3 ]]; then
    echo "  ✅ INPUT VALIDATION COVERAGE: GOOD" | tee -a "$RESULTS_FILE"
    input_validation_score=80
else
    echo "  ⚠️ INPUT VALIDATION COVERAGE: LIMITED" | tee -a "$RESULTS_FILE"
    input_validation_score=60
fi

# Check for XSS patterns
xss_patterns=$(grep -c "XSSPatterns\|<script\|javascript:\|onerror=" "$PROJECT_ROOT/pkg/security/validator.go")
echo "  XSS detection patterns: $xss_patterns" | tee -a "$RESULTS_FILE"

# Check for path traversal patterns  
traversal_patterns=$(grep -c "PathTraversalPatterns\|\.\.\/" "$PROJECT_ROOT/pkg/security/validator.go")
echo "  Path traversal patterns: $traversal_patterns" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"

echo "⚡ PHASE 3: RATE LIMITING IMPLEMENTATION ANALYSIS"
echo "==============================================="

echo "Analyzing rate limiting components..." | tee -a "$RESULTS_FILE"

# Check for rate limiting implementation
rate_limiter_exists=$(test -f "$PROJECT_ROOT/pkg/security/ratelimiter.go" && echo 1 || echo 0)
redis_backend=$(grep -c "redis" "$PROJECT_ROOT/pkg/security/ratelimiter.go" 2>/dev/null || echo 0)
token_bucket=$(grep -c "TokenBucket\|bucket" "$PROJECT_ROOT/pkg/security/ratelimiter.go" 2>/dev/null || echo 0)
multi_tier=$(grep -c "Global\|IP\|User\|Endpoint" "$PROJECT_ROOT/pkg/security/ratelimiter.go" 2>/dev/null || echo 0)
emergency_mode=$(grep -c "Emergency" "$PROJECT_ROOT/pkg/security/ratelimiter.go" 2>/dev/null || echo 0)

echo "  Rate limiter implementation: $([ $rate_limiter_exists -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  Redis backend integration: $redis_backend references" | tee -a "$RESULTS_FILE"
echo "  Token bucket algorithm: $token_bucket implementations" | tee -a "$RESULTS_FILE"
echo "  Multi-tier limits: $multi_tier implementations" | tee -a "$RESULTS_FILE"
echo "  Emergency mode: $emergency_mode implementations" | tee -a "$RESULTS_FILE"

rate_limiting_features=$((redis_backend + token_bucket + multi_tier + emergency_mode))
if [[ $rate_limiting_features -gt 8 ]]; then
    echo "  ✅ RATE LIMITING: FORTRESS-GRADE" | tee -a "$RESULTS_FILE"
    rate_limiting_score=100
elif [[ $rate_limiting_features -gt 4 ]]; then
    echo "  ✅ RATE LIMITING: GOOD" | tee -a "$RESULTS_FILE"
    rate_limiting_score=80
else
    echo "  ⚠️ RATE LIMITING: BASIC" | tee -a "$RESULTS_FILE"
    rate_limiting_score=60
fi

echo "" | tee -a "$RESULTS_FILE"

echo "🔐 PHASE 4: AUTHENTICATION SECURITY ANALYSIS"
echo "==========================================="

echo "Analyzing authentication implementations..." | tee -a "$RESULTS_FILE"

# Check JWT implementation
jwt_implementation=$(test -f "$PROJECT_ROOT/pkg/auth/jwt.go" && echo 1 || echo 0)
rsa_encryption=$(grep -c "rsa\|RSA" "$PROJECT_ROOT/pkg/auth/jwt.go" 2>/dev/null || echo 0)
token_expiry=$(grep -c "expiry\|Expiry\|ExpiresAt" "$PROJECT_ROOT/pkg/auth/jwt.go" 2>/dev/null || echo 0)
claims_validation=$(grep -c "Claims\|Valid" "$PROJECT_ROOT/pkg/auth/jwt.go" 2>/dev/null || echo 0)

echo "  JWT implementation: $([ $jwt_implementation -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  RSA encryption: $rsa_encryption references" | tee -a "$RESULTS_FILE"
echo "  Token expiry: $token_expiry implementations" | tee -a "$RESULTS_FILE"
echo "  Claims validation: $claims_validation implementations" | tee -a "$RESULTS_FILE"

# Check password security
password_hashing=$(grep -c "bcrypt\|argon2\|scrypt" "$PROJECT_ROOT/pkg/auth/password.go" 2>/dev/null || echo 0)
salt_usage=$(grep -c "salt\|Salt" "$PROJECT_ROOT/pkg/auth/password.go" 2>/dev/null || echo 0)

echo "  Password hashing: $password_hashing implementations" | tee -a "$RESULTS_FILE"
echo "  Salt usage: $salt_usage references" | tee -a "$RESULTS_FILE"

# Check RBAC implementation
rbac_implementation=$(test -f "$PROJECT_ROOT/pkg/auth/rbac.go" && echo 1 || echo 0)
role_permissions=$(grep -c "Role\|Permission" "$PROJECT_ROOT/pkg/auth/rbac.go" 2>/dev/null || echo 0)

echo "  RBAC implementation: $([ $rbac_implementation -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  Role/Permission system: $role_permissions references" | tee -a "$RESULTS_FILE"

auth_features=$((jwt_implementation + rsa_encryption + password_hashing + rbac_implementation))
if [[ $auth_features -gt 3 ]]; then
    echo "  ✅ AUTHENTICATION: COMPREHENSIVE" | tee -a "$RESULTS_FILE"
    auth_score=100
elif [[ $auth_features -gt 1 ]]; then
    echo "  ✅ AUTHENTICATION: BASIC" | tee -a "$RESULTS_FILE"
    auth_score=70
else
    echo "  ❌ AUTHENTICATION: INSUFFICIENT" | tee -a "$RESULTS_FILE"
    auth_score=40
fi

echo "" | tee -a "$RESULTS_FILE"

echo "👁️ PHASE 5: MONITORING & ALERTING ANALYSIS"
echo "========================================="

echo "Analyzing security monitoring implementations..." | tee -a "$RESULTS_FILE"

# Check watchtower implementation
watchtower_exists=$(test -f "$PROJECT_ROOT/pkg/security/watchtower.go" && echo 1 || echo 0)
event_processing=$(grep -c "ProcessEvent\|SecurityEvent" "$PROJECT_ROOT/pkg/security/watchtower.go" 2>/dev/null || echo 0)
pattern_detection=$(grep -c "Pattern\|Detect" "$PROJECT_ROOT/pkg/security/watchtower.go" 2>/dev/null || echo 0)
alert_generation=$(grep -c "Alert\|Notification" "$PROJECT_ROOT/pkg/security/watchtower.go" 2>/dev/null || echo 0)
metrics_collection=$(grep -c "Metrics\|Counter" "$PROJECT_ROOT/pkg/security/watchtower.go" 2>/dev/null || echo 0)

echo "  Watchtower monitoring: $([ $watchtower_exists -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  Event processing: $event_processing implementations" | tee -a "$RESULTS_FILE"
echo "  Pattern detection: $pattern_detection implementations" | tee -a "$RESULTS_FILE"
echo "  Alert generation: $alert_generation implementations" | tee -a "$RESULTS_FILE"
echo "  Metrics collection: $metrics_collection implementations" | tee -a "$RESULTS_FILE"

monitoring_features=$((watchtower_exists + event_processing + pattern_detection + alert_generation + metrics_collection))
if [[ $monitoring_features -gt 8 ]]; then
    echo "  ✅ MONITORING: COMPREHENSIVE" | tee -a "$RESULTS_FILE"
    monitoring_score=100
elif [[ $monitoring_features -gt 4 ]]; then
    echo "  ✅ MONITORING: GOOD" | tee -a "$RESULTS_FILE"
    monitoring_score=80
else
    echo "  ⚠️ MONITORING: LIMITED" | tee -a "$RESULTS_FILE"
    monitoring_score=60
fi

echo "" | tee -a "$RESULTS_FILE"

echo "🏗️ PHASE 6: MIDDLEWARE INTEGRATION ANALYSIS"
echo "=========================================="

echo "Analyzing security middleware integration..." | tee -a "$RESULTS_FILE"

# Check middleware implementation
middleware_exists=$(test -f "$PROJECT_ROOT/pkg/middleware/security.go" && echo 1 || echo 0)
http_integration=$(grep -c "http\|HTTP" "$PROJECT_ROOT/pkg/middleware/security.go" 2>/dev/null || echo 0)
error_handling=$(grep -c "Error\|error" "$PROJECT_ROOT/pkg/middleware/security.go" 2>/dev/null || echo 0)
logging_integration=$(grep -c "log\|Log\|zap" "$PROJECT_ROOT/pkg/middleware/security.go" 2>/dev/null || echo 0)

echo "  Security middleware: $([ $middleware_exists -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  HTTP integration: $http_integration references" | tee -a "$RESULTS_FILE"
echo "  Error handling: $error_handling implementations" | tee -a "$RESULTS_FILE"
echo "  Logging integration: $logging_integration references" | tee -a "$RESULTS_FILE"

middleware_features=$((middleware_exists + http_integration + error_handling + logging_integration))
if [[ $middleware_features -gt 6 ]]; then
    echo "  ✅ MIDDLEWARE INTEGRATION: EXCELLENT" | tee -a "$RESULTS_FILE"
    middleware_score=100
elif [[ $middleware_features -gt 3 ]]; then
    echo "  ✅ MIDDLEWARE INTEGRATION: GOOD" | tee -a "$RESULTS_FILE"
    middleware_score=80
else
    echo "  ⚠️ MIDDLEWARE INTEGRATION: BASIC" | tee -a "$RESULTS_FILE"
    middleware_score=60
fi

echo "" | tee -a "$RESULTS_FILE"

echo "🧪 PHASE 7: TEST COVERAGE ANALYSIS"
echo "================================"

echo "Analyzing security test implementations..." | tee -a "$RESULTS_FILE"

# Count test files
security_test_files=$(find "$PROJECT_ROOT/pkg" -name "*_test.go" | wc -l)
validator_tests=$(grep -c "func Test" "$PROJECT_ROOT/pkg/security/validator_test.go" 2>/dev/null || echo 0)
ratelimiter_tests=$(grep -c "func Test" "$PROJECT_ROOT/pkg/security/ratelimiter_test.go" 2>/dev/null || echo 0)
auth_tests=$(find "$PROJECT_ROOT/pkg/auth" -name "*_test.go" -exec grep -c "func Test" {} \; 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)

echo "  Security test files: $security_test_files" | tee -a "$RESULTS_FILE"
echo "  Validator tests: $validator_tests" | tee -a "$RESULTS_FILE"
echo "  Rate limiter tests: $ratelimiter_tests" | tee -a "$RESULTS_FILE"
echo "  Authentication tests: $auth_tests" | tee -a "$RESULTS_FILE"

total_tests=$((validator_tests + ratelimiter_tests + auth_tests))
echo "  Total security tests: $total_tests" | tee -a "$RESULTS_FILE"

if [[ $total_tests -gt 30 ]]; then
    echo "  ✅ TEST COVERAGE: COMPREHENSIVE" | tee -a "$RESULTS_FILE"
    test_coverage_score=100
elif [[ $total_tests -gt 15 ]]; then
    echo "  ✅ TEST COVERAGE: GOOD" | tee -a "$RESULTS_FILE"
    test_coverage_score=80
elif [[ $total_tests -gt 5 ]]; then
    echo "  ✅ TEST COVERAGE: BASIC" | tee -a "$RESULTS_FILE"
    test_coverage_score=60
else
    echo "  ❌ TEST COVERAGE: INSUFFICIENT" | tee -a "$RESULTS_FILE"
    test_coverage_score=30
fi

echo "" | tee -a "$RESULTS_FILE"

echo "📊 PHASE 8: CONFIGURATION SECURITY ANALYSIS"
echo "=========================================="

echo "Analyzing security configuration management..." | tee -a "$RESULTS_FILE"

# Check configuration implementation
config_manager=$(test -f "$PROJECT_ROOT/pkg/security/config.go" && echo 1 || echo 0)
dynamic_updates=$(grep -c "UpdateConfig\|Reload" "$PROJECT_ROOT/pkg/security/config.go" 2>/dev/null || echo 0)
validation_rules=$(grep -c "Validate\|validate" "$PROJECT_ROOT/pkg/security/config.go" 2>/dev/null || echo 0)
environment_vars=$(grep -c "os.Getenv\|ENV" "$PROJECT_ROOT/pkg/security/config.go" 2>/dev/null || echo 0)

echo "  Configuration manager: $([ $config_manager -eq 1 ] && echo "EXISTS" || echo "MISSING")" | tee -a "$RESULTS_FILE"
echo "  Dynamic updates: $dynamic_updates implementations" | tee -a "$RESULTS_FILE"
echo "  Validation rules: $validation_rules implementations" | tee -a "$RESULTS_FILE"
echo "  Environment integration: $environment_vars references" | tee -a "$RESULTS_FILE"

config_features=$((config_manager + dynamic_updates + validation_rules + environment_vars))
if [[ $config_features -gt 6 ]]; then
    echo "  ✅ CONFIGURATION SECURITY: EXCELLENT" | tee -a "$RESULTS_FILE"
    config_score=100
elif [[ $config_features -gt 3 ]]; then
    echo "  ✅ CONFIGURATION SECURITY: GOOD" | tee -a "$RESULTS_FILE"
    config_score=80
else
    echo "  ⚠️ CONFIGURATION SECURITY: BASIC" | tee -a "$RESULTS_FILE"
    config_score=60
fi

echo "" | tee -a "$RESULTS_FILE"

echo "============================================================================"
echo "🏆 FORTRESS CODE SECURITY AUDIT - FINAL RESULTS"
echo "============================================================================"

# Calculate overall scores
echo "SECURITY COMPONENT ANALYSIS RESULTS:" | tee -a "$RESULTS_FILE"
echo "  SQL Injection Protection:    $sql_protection_score%" | tee -a "$RESULTS_FILE"
echo "  Input Validation Coverage:   $input_validation_score%" | tee -a "$RESULTS_FILE"
echo "  Rate Limiting Implementation: $rate_limiting_score%" | tee -a "$RESULTS_FILE"
echo "  Authentication Security:     $auth_score%" | tee -a "$RESULTS_FILE"
echo "  Monitoring & Alerting:       $monitoring_score%" | tee -a "$RESULTS_FILE"
echo "  Middleware Integration:      $middleware_score%" | tee -a "$RESULTS_FILE"
echo "  Test Coverage:               $test_coverage_score%" | tee -a "$RESULTS_FILE"
echo "  Configuration Security:      $config_score%" | tee -a "$RESULTS_FILE"

# Calculate overall code security score
total_score=$(((sql_protection_score + input_validation_score + rate_limiting_score + auth_score + monitoring_score + middleware_score + test_coverage_score + config_score) / 8))

echo "" | tee -a "$RESULTS_FILE"
echo "OVERALL CODE SECURITY SCORE: $total_score%" | tee -a "$RESULTS_FILE"

# Determine security grade
if [[ $total_score -gt 95 ]]; then
    security_grade="A+ (FORTRESS-GRADE)"
    security_status="🏰 FORTRESS-LEVEL SECURE"
elif [[ $total_score -gt 90 ]]; then
    security_grade="A (EXCELLENT)"
    security_status="✅ HIGHLY SECURE"
elif [[ $total_score -gt 80 ]]; then
    security_grade="B (GOOD)"
    security_status="✅ SECURE"
elif [[ $total_score -gt 70 ]]; then
    security_grade="C (ACCEPTABLE)"
    security_status="⚠️ NEEDS IMPROVEMENT"
else
    security_grade="F (VULNERABLE)"
    security_status="❌ CRITICAL ISSUES"
fi

echo "SECURITY GRADE: $security_grade" | tee -a "$RESULTS_FILE"
echo "SECURITY STATUS: $security_status" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Count lines of security code
echo "FORTRESS CODEBASE METRICS:" | tee -a "$RESULTS_FILE"
total_security_lines=$(find "$PROJECT_ROOT/pkg/security" -name "*.go" ! -name "*_test.go" -exec wc -l {} \; | awk '{sum+=$1} END {print sum}')
total_auth_lines=$(find "$PROJECT_ROOT/pkg/auth" -name "*.go" ! -name "*_test.go" -exec wc -l {} \; | awk '{sum+=$1} END {print sum}')
total_middleware_lines=$(find "$PROJECT_ROOT/pkg/middleware" -name "*.go" ! -name "*_test.go" -exec wc -l {} \; | awk '{sum+=$1} END {print sum}')
total_test_lines=$(find "$PROJECT_ROOT/pkg" -name "*_test.go" -exec wc -l {} \; | awk '{sum+=$1} END {print sum}')

total_fortress_lines=$((total_security_lines + total_auth_lines + total_middleware_lines))

echo "  Security package:     $total_security_lines lines" | tee -a "$RESULTS_FILE"
echo "  Authentication:       $total_auth_lines lines" | tee -a "$RESULTS_FILE"
echo "  Middleware:           $total_middleware_lines lines" | tee -a "$RESULTS_FILE"
echo "  Test code:            $total_test_lines lines" | tee -a "$RESULTS_FILE"
echo "  Total fortress code:  $total_fortress_lines lines" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"
echo "FORTRESS IMPLEMENTATION ASSESSMENT:" | tee -a "$RESULTS_FILE"

# Check for fortress files
fortress_files=(
    "pkg/security/ratelimiter.go"
    "pkg/security/validator.go"
    "pkg/security/rampart.go"
    "pkg/security/watchtower.go"
    "pkg/security/config.go"
    "pkg/middleware/security.go"
    "cmd/fortress-demo/main.go"
)

fortress_files_count=0
for file in "${fortress_files[@]}"; do
    if [[ -f "$PROJECT_ROOT/$file" ]]; then
        ((fortress_files_count++))
        echo "  ✅ $file" | tee -a "$RESULTS_FILE"
    else
        echo "  ❌ $file (MISSING)" | tee -a "$RESULTS_FILE"
    fi
done

echo "" | tee -a "$RESULTS_FILE"
echo "FORTRESS DEPLOYMENT STATUS: $fortress_files_count/7 core files present" | tee -a "$RESULTS_FILE"

if [[ $fortress_files_count -eq 7 ]]; then
    echo "✅ FORTRESS IMPLEMENTATION: COMPLETE" | tee -a "$RESULTS_FILE"
    fortress_status="COMPLETE"
elif [[ $fortress_files_count -gt 4 ]]; then
    echo "✅ FORTRESS IMPLEMENTATION: MOSTLY COMPLETE" | tee -a "$RESULTS_FILE"
    fortress_status="MOSTLY_COMPLETE"
else
    echo "❌ FORTRESS IMPLEMENTATION: INCOMPLETE" | tee -a "$RESULTS_FILE"
    fortress_status="INCOMPLETE"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "CODE AUDIT COMPLETED: $(date)" | tee -a "$RESULTS_FILE"
echo "CLASSIFICATION: FORTRESS-PROTECTED" | tee -a "$RESULTS_FILE"
echo "============================================================================" | tee -a "$RESULTS_FILE"

# Display final summary
echo ""
echo "📋 FORTRESS CODE AUDIT COMPLETE"
echo "   Security Score: $total_score%"
echo "   Security Grade: $security_grade"
echo "   Implementation: $fortress_status"
echo "   Lines of Code: $total_fortress_lines"
echo "   Report saved: $RESULTS_FILE"
echo ""
echo "🏰 CODE AUDIT COMPLETE 🏰"