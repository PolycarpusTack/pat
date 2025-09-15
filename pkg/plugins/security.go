package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// SecurityScanner performs security analysis on plugins
type SecurityScanner struct {
	logger    Logger
	threatDB  ThreatDatabase
	analyzer  StaticAnalyzer
	sandbox   SandboxRunner
	validator *Validator
}

// NewSecurityScanner creates a new security scanner
func NewSecurityScanner(logger Logger, threatDB ThreatDatabase, analyzer StaticAnalyzer, sandbox SandboxRunner) *SecurityScanner {
	return &SecurityScanner{
		logger:    logger,
		threatDB:  threatDB,
		analyzer:  analyzer,
		sandbox:   sandbox,
		validator: NewValidator(),
	}
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	PluginID        string             `json:"plugin_id"`
	ScanID          string             `json:"scan_id"`
	Timestamp       time.Time          `json:"timestamp"`
	OverallRisk     RiskLevel          `json:"overall_risk"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities"`
	Threats         []ThreatMatch      `json:"threats"`
	StaticAnalysis  StaticAnalysisResult `json:"static_analysis"`
	SandboxResults  SandboxResult      `json:"sandbox_results"`
	Recommendations []string           `json:"recommendations"`
	Passed          bool               `json:"passed"`
}

// RiskLevel represents security risk levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    RiskLevel `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Location    Location  `json:"location"`
	Remediation string    `json:"remediation"`
	CVEID       string    `json:"cve_id,omitempty"`
}

// ThreatMatch represents a match with known threat patterns
type ThreatMatch struct {
	ThreatID    string    `json:"threat_id"`
	Type        string    `json:"type"`
	Severity    RiskLevel `json:"severity"`
	Pattern     string    `json:"pattern"`
	Location    Location  `json:"location"`
	Description string    `json:"description"`
}

// Location represents code location
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Length int    `json:"length"`
}

// StaticAnalysisResult contains static analysis results
type StaticAnalysisResult struct {
	ComplexityScore     int                    `json:"complexity_score"`
	SecurityScore       int                    `json:"security_score"`
	QualityScore        int                    `json:"quality_score"`
	FunctionCount       int                    `json:"function_count"`
	VariableCount       int                    `json:"variable_count"`
	APICallCount        int                    `json:"api_call_count"`
	ExternalDependencies []string              `json:"external_dependencies"`
	Metrics             map[string]interface{} `json:"metrics"`
}

// SandboxResult contains sandbox execution results
type SandboxResult struct {
	Executed        bool                   `json:"executed"`
	ExecutionTime   time.Duration          `json:"execution_time"`
	MemoryUsage     int64                  `json:"memory_usage"`
	CPUTime         time.Duration          `json:"cpu_time"`
	NetworkCalls    []NetworkCall          `json:"network_calls"`
	FileOperations  []FileOperation        `json:"file_operations"`
	SystemCalls     []SystemCall           `json:"system_calls"`
	Errors          []string               `json:"errors"`
	Behaviors       map[string]interface{} `json:"behaviors"`
}

// NetworkCall represents a network operation
type NetworkCall struct {
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Headers     map[string]string `json:"headers"`
	Timestamp   time.Time `json:"timestamp"`
	Status      int       `json:"status"`
	Blocked     bool      `json:"blocked"`
	BlockReason string    `json:"block_reason,omitempty"`
}

// FileOperation represents a file operation
type FileOperation struct {
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Blocked   bool      `json:"blocked"`
	Reason    string    `json:"reason,omitempty"`
}

// SystemCall represents a system call
type SystemCall struct {
	Name      string                 `json:"name"`
	Args      map[string]interface{} `json:"args"`
	Timestamp time.Time              `json:"timestamp"`
	Blocked   bool                   `json:"blocked"`
	Reason    string                 `json:"reason,omitempty"`
}

// ScanPlugin performs comprehensive security scan
func (s *SecurityScanner) ScanPlugin(code string, metadata *PluginMetadata) (*ScanResult, error) {
	scanID := s.generateScanID(code)
	
	result := &ScanResult{
		PluginID:        metadata.ID,
		ScanID:          scanID,
		Timestamp:       time.Now(),
		Vulnerabilities: []Vulnerability{},
		Threats:         []ThreatMatch{},
		Recommendations: []string{},
	}

	s.logger.Info("Starting security scan", map[string]interface{}{
		"plugin_id": metadata.ID,
		"scan_id":   scanID,
	})

	// 1. Static code analysis
	staticResult, err := s.performStaticAnalysis(code, metadata)
	if err != nil {
		return nil, errors.Wrap(err, "static analysis failed")
	}
	result.StaticAnalysis = *staticResult

	// 2. Threat pattern matching
	threats, err := s.detectThreats(code)
	if err != nil {
		return nil, errors.Wrap(err, "threat detection failed")
	}
	result.Threats = threats

	// 3. Vulnerability scanning
	vulnerabilities, err := s.scanVulnerabilities(code, metadata)
	if err != nil {
		return nil, errors.Wrap(err, "vulnerability scanning failed")
	}
	result.Vulnerabilities = vulnerabilities

	// 4. Sandbox execution analysis (if safe enough)
	if s.shouldRunSandbox(result) {
		sandboxResult, err := s.runSandboxAnalysis(code, metadata)
		if err != nil {
			s.logger.Warn("Sandbox analysis failed", map[string]interface{}{
				"plugin_id": metadata.ID,
				"error":     err.Error(),
			})
		} else {
			result.SandboxResults = *sandboxResult
		}
	}

	// 5. Calculate overall risk and generate recommendations
	s.calculateRiskLevel(result)
	s.generateRecommendations(result)

	// 6. Determine if scan passed
	result.Passed = s.evaluatePassCriteria(result)

	s.logger.Info("Security scan completed", map[string]interface{}{
		"plugin_id":    metadata.ID,
		"scan_id":      scanID,
		"risk_level":   result.OverallRisk,
		"passed":       result.Passed,
		"vuln_count":   len(result.Vulnerabilities),
		"threat_count": len(result.Threats),
	})

	return result, nil
}

// performStaticAnalysis analyzes code without execution
func (s *SecurityScanner) performStaticAnalysis(code string, metadata *PluginMetadata) (*StaticAnalysisResult, error) {
	result := &StaticAnalysisResult{
		ExternalDependencies: []string{},
		Metrics:              make(map[string]interface{}),
	}

	// Complexity analysis
	result.ComplexityScore = s.calculateComplexity(code)
	
	// Function and variable counting
	result.FunctionCount = s.countFunctions(code)
	result.VariableCount = s.countVariables(code)
	result.APICallCount = s.countAPICalls(code)

	// Security scoring
	result.SecurityScore = s.calculateSecurityScore(code, metadata)
	
	// Quality scoring
	result.QualityScore = s.calculateQualityScore(code)

	// Detect external dependencies
	result.ExternalDependencies = s.detectExternalDependencies(code)

	return result, nil
}

// detectThreats identifies known threat patterns
func (s *SecurityScanner) detectThreats(code string) ([]ThreatMatch, error) {
	var threats []ThreatMatch

	// Load threat patterns from database
	patterns, err := s.threatDB.GetThreatPatterns(context.Background())
	if err != nil {
		return nil, err
	}

	// Check each pattern
	for _, pattern := range patterns {
		matches := s.findPatternMatches(code, pattern)
		for _, match := range matches {
			threats = append(threats, ThreatMatch{
				ThreatID:    pattern.ID,
				Type:        pattern.Type,
				Severity:    RiskLevel(pattern.Severity),
				Pattern:     pattern.Pattern,
				Location:    match.Location,
				Description: pattern.Description,
			})
		}
	}

	return threats, nil
}

// scanVulnerabilities checks for security vulnerabilities
func (s *SecurityScanner) scanVulnerabilities(code string, metadata *PluginMetadata) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// Check for common JavaScript vulnerabilities
	vulnChecks := []struct {
		pattern     string
		vulnType    string
		severity    RiskLevel
		title       string
		description string
		remediation string
	}{
		{
			pattern:     `eval\s*\(`,
			vulnType:    "code_injection",
			severity:    RiskLevelHigh,
			title:       "Code Injection via eval()",
			description: "Use of eval() can lead to code injection vulnerabilities",
			remediation: "Avoid using eval(). Use JSON.parse() for parsing JSON data.",
		},
		{
			pattern:     `innerHTML\s*=`,
			vulnType:    "xss",
			severity:    RiskLevelMedium,
			title:       "Potential XSS via innerHTML",
			description: "Direct assignment to innerHTML can lead to XSS vulnerabilities",
			remediation: "Use textContent or properly sanitize HTML content",
		},
		{
			pattern:     `document\.write\s*\(`,
			vulnType:    "xss",
			severity:    RiskLevelMedium,
			title:       "Potential XSS via document.write",
			description: "Use of document.write can lead to XSS vulnerabilities",
			remediation: "Use safer DOM manipulation methods",
		},
		{
			pattern:     `setTimeout\s*\(\s*["'][^"']*["']\s*,`,
			vulnType:    "code_injection",
			severity:    RiskLevelMedium,
			title:       "Code Injection via setTimeout string",
			description: "Passing strings to setTimeout can lead to code injection",
			remediation: "Pass functions instead of strings to setTimeout",
		},
		{
			pattern:     `new\s+Function\s*\(`,
			vulnType:    "code_injection",
			severity:    RiskLevelHigh,
			title:       "Code Injection via Function constructor",
			description: "Function constructor can be used for code injection",
			remediation: "Avoid using Function constructor",
		},
	}

	for _, check := range vulnChecks {
		matches := s.findRegexMatches(code, check.pattern)
		for _, match := range matches {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          s.generateVulnID(check.vulnType, match.Location),
				Type:        check.vulnType,
				Severity:    check.severity,
				Title:       check.title,
				Description: check.description,
				Location:    match.Location,
				Remediation: check.remediation,
			})
		}
	}

	return vulnerabilities, nil
}

// runSandboxAnalysis executes code in a secure sandbox
func (s *SecurityScanner) runSandboxAnalysis(code string, metadata *PluginMetadata) (*SandboxResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.sandbox.Execute(ctx, code, metadata)
}

// calculateComplexity calculates cyclomatic complexity
func (s *SecurityScanner) calculateComplexity(code string) int {
	// Count control flow statements
	patterns := []string{
		`if\s*\(`,
		`else\s+if\s*\(`,
		`while\s*\(`,
		`for\s*\(`,
		`switch\s*\(`,
		`case\s+`,
		`catch\s*\(`,
		`\?\s*.*\s*:`, // ternary operator
	}

	complexity := 1 // base complexity
	for _, pattern := range patterns {
		matches := s.findRegexMatches(code, pattern)
		complexity += len(matches)
	}

	return complexity
}

// countFunctions counts function definitions
func (s *SecurityScanner) countFunctions(code string) int {
	patterns := []string{
		`function\s+\w+\s*\(`,
		`\w+\s*:\s*function\s*\(`,
		`const\s+\w+\s*=\s*\(.*\)\s*=>`,
		`let\s+\w+\s*=\s*\(.*\)\s*=>`,
		`var\s+\w+\s*=\s*\(.*\)\s*=>`,
	}

	count := 0
	for _, pattern := range patterns {
		matches := s.findRegexMatches(code, pattern)
		count += len(matches)
	}

	return count
}

// countVariables counts variable declarations
func (s *SecurityScanner) countVariables(code string) int {
	patterns := []string{
		`var\s+\w+`,
		`let\s+\w+`,
		`const\s+\w+`,
	}

	count := 0
	for _, pattern := range patterns {
		matches := s.findRegexMatches(code, pattern)
		count += len(matches)
	}

	return count
}

// countAPICalls counts API calls
func (s *SecurityScanner) countAPICalls(code string) int {
	patterns := []string{
		`Email\.`,
		`Http\.`,
		`Storage\.`,
		`Utils\.`,
		`console\.`,
	}

	count := 0
	for _, pattern := range patterns {
		matches := s.findRegexMatches(code, pattern)
		count += len(matches)
	}

	return count
}

// calculateSecurityScore calculates security score (0-100)
func (s *SecurityScanner) calculateSecurityScore(code string, metadata *PluginMetadata) int {
	score := 100

	// Deduct points for security issues
	if strings.Contains(code, "eval(") {
		score -= 30
	}
	if strings.Contains(code, "innerHTML") {
		score -= 15
	}
	if strings.Contains(code, "document.write") {
		score -= 15
	}
	if strings.Contains(code, "setTimeout") && strings.Contains(code, `"`) {
		score -= 20
	}

	// Bonus points for good practices
	if strings.Contains(code, "try") && strings.Contains(code, "catch") {
		score += 5
	}
	if len(metadata.Permissions) < 3 {
		score += 10 // Principle of least privilege
	}

	if score < 0 {
		score = 0
	}

	return score
}

// calculateQualityScore calculates code quality score (0-100)
func (s *SecurityScanner) calculateQualityScore(code string) int {
	score := 100

	// Check for best practices
	lines := strings.Split(code, "\n")
	commentLines := 0
	for _, line := range lines {
		if strings.Contains(strings.TrimSpace(line), "//") || strings.Contains(strings.TrimSpace(line), "/*") {
			commentLines++
		}
	}

	// Comment ratio
	commentRatio := float64(commentLines) / float64(len(lines))
	if commentRatio < 0.1 {
		score -= 10
	} else if commentRatio > 0.3 {
		score += 10
	}

	// Check for proper error handling
	if !strings.Contains(code, "try") || !strings.Contains(code, "catch") {
		score -= 15
	}

	// Check for proper function structure
	if !strings.Contains(code, "function main") {
		score -= 10
	}

	return score
}

// detectExternalDependencies finds external dependencies
func (s *SecurityScanner) detectExternalDependencies(code string) []string {
	var dependencies []string

	// This would typically parse imports, requires, etc.
	// For now, we'll check for common patterns
	patterns := []string{
		`require\s*\(\s*["']([^"']+)["']\s*\)`,
		`import\s+.*\s+from\s+["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			if len(match) > 1 {
				dependencies = append(dependencies, match[1])
			}
		}
	}

	return dependencies
}

// Helper methods
func (s *SecurityScanner) shouldRunSandbox(result *ScanResult) bool {
	// Don't run sandbox if there are critical vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == RiskLevelCritical {
			return false
		}
	}
	return true
}

func (s *SecurityScanner) calculateRiskLevel(result *ScanResult) {
	risk := RiskLevelLow

	// Check vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == RiskLevelCritical {
			risk = RiskLevelCritical
			break
		} else if vuln.Severity == RiskLevelHigh && risk != RiskLevelCritical {
			risk = RiskLevelHigh
		} else if vuln.Severity == RiskLevelMedium && risk == RiskLevelLow {
			risk = RiskLevelMedium
		}
	}

	// Check threats
	for _, threat := range result.Threats {
		if threat.Severity == RiskLevelCritical {
			risk = RiskLevelCritical
			break
		} else if threat.Severity == RiskLevelHigh && risk != RiskLevelCritical {
			risk = RiskLevelHigh
		} else if threat.Severity == RiskLevelMedium && risk == RiskLevelLow {
			risk = RiskLevelMedium
		}
	}

	result.OverallRisk = risk
}

func (s *SecurityScanner) generateRecommendations(result *ScanResult) {
	recommendations := []string{}

	if result.StaticAnalysis.SecurityScore < 70 {
		recommendations = append(recommendations, "Improve security practices by avoiding eval(), innerHTML, and other dangerous APIs")
	}

	if result.StaticAnalysis.ComplexityScore > 10 {
		recommendations = append(recommendations, "Consider refactoring to reduce cyclomatic complexity")
	}

	if len(result.Vulnerabilities) > 0 {
		recommendations = append(recommendations, "Address identified security vulnerabilities before publication")
	}

	if len(result.Threats) > 0 {
		recommendations = append(recommendations, "Review and mitigate detected threat patterns")
	}

	result.Recommendations = recommendations
}

func (s *SecurityScanner) evaluatePassCriteria(result *ScanResult) bool {
	// No critical vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == RiskLevelCritical {
			return false
		}
	}

	// No critical threats
	for _, threat := range result.Threats {
		if threat.Severity == RiskLevelCritical {
			return false
		}
	}

	// Minimum security score
	if result.StaticAnalysis.SecurityScore < 60 {
		return false
	}

	return true
}

func (s *SecurityScanner) HasVulnerabilities() bool {
	// This method would be implemented on ScanResult
	return false
}

// Helper interfaces and types
type ThreatDatabase interface {
	GetThreatPatterns(ctx context.Context) ([]ThreatPattern, error)
}

type ThreatPattern struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type StaticAnalyzer interface {
	Analyze(code string) (*StaticAnalysisResult, error)
}

type SandboxRunner interface {
	Execute(ctx context.Context, code string, metadata *PluginMetadata) (*SandboxResult, error)
}

// Helper methods for pattern matching
func (s *SecurityScanner) findPatternMatches(code string, pattern ThreatPattern) []PatternMatch {
	return s.findRegexMatches(code, pattern.Pattern)
}

func (s *SecurityScanner) findRegexMatches(code string, pattern string) []PatternMatch {
	var matches []PatternMatch
	
	re, err := regexp.Compile(pattern)
	if err != nil {
		return matches
	}

	lines := strings.Split(code, "\n")
	for lineNum, line := range lines {
		indices := re.FindAllStringIndex(line, -1)
		for _, index := range indices {
			matches = append(matches, PatternMatch{
				Location: Location{
					Line:   lineNum + 1,
					Column: index[0] + 1,
					Length: index[1] - index[0],
				},
			})
		}
	}

	return matches
}

type PatternMatch struct {
	Location Location
}

func (s *SecurityScanner) generateScanID(code string) string {
	hash := sha256.Sum256([]byte(code + time.Now().String()))
	return hex.EncodeToString(hash[:])[:16]
}

func (s *SecurityScanner) generateVulnID(vulnType string, location Location) string {
	data := fmt.Sprintf("%s_%d_%d", vulnType, location.Line, location.Column)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:12]
}