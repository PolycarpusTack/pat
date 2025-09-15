package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
	"github.com/mailhog/Pat/config"
	"github.com/mailhog/Pat/pkg/fortress"
)

// FortressSecurityMonitor provides continuous security monitoring and alerting
type FortressSecurityMonitor struct {
	fortress      *fortress.Service
	config        *config.Config
	alertManager  *SecurityAlertManager
	metrics       *SecurityMetrics
	threatIntel   *ThreatIntelligence
	logger        *SecurityLogger
	ctx           context.Context
	cancel        context.CancelFunc
	running       bool
	mutex         sync.RWMutex
}

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
	VulnerabilityCount      prometheus.Gauge
	SecurityTestCoverage    prometheus.Gauge
	AuthenticationFailures  prometheus.Counter
	APISecurityViolations   prometheus.Counter
	SQLInjectionAttempts    prometheus.Counter
	XSSAttempts            prometheus.Counter
	RateLimitViolations    prometheus.Counter
	UnauthorizedAccess     prometheus.Counter
	ThreatDetections       prometheus.Counter
	ComplianceScore        prometheus.Gauge
	SecurityAlerts         prometheus.Counter
	ResponseTime           prometheus.Histogram
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
}

// SecurityAlertManager handles security alert generation and notification
type SecurityAlertManager struct {
	alerts      []SecurityAlert
	mutex       sync.RWMutex
	channels    map[string]chan SecurityAlert
	rules       []AlertRule
	logger      *SecurityLogger
}

// AlertRule defines conditions for generating security alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Severity    string                 `json:"severity"`
	Action      string                 `json:"action"`
	Enabled     bool                   `json:"enabled"`
	Threshold   map[string]interface{} `json:"threshold"`
	Recipients  []string               `json:"recipients"`
}

// ThreatIntelligence provides threat intelligence integration
type ThreatIntelligence struct {
	sources     map[string]ThreatSource
	indicators  []ThreatIndicator
	mutex       sync.RWMutex
	lastUpdate  time.Time
}

// ThreatSource represents a threat intelligence source
type ThreatSource struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	APIKey      string    `json:"api_key"`
	LastUpdate  time.Time `json:"last_update"`
	Enabled     bool      `json:"enabled"`
}

// ThreatIndicator represents an indicator of compromise
type ThreatIndicator struct {
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Confidence  float64                `json:"confidence"`
	Source      string                 `json:"source"`
	Tags        []string               `json:"tags"`
	Details     map[string]interface{} `json:"details"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
}

// SecurityLogger provides structured security logging
type SecurityLogger struct {
	logger *log.Logger
	file   *os.File
	mutex  sync.Mutex
}

// NewFortressSecurityMonitor creates a new security monitor instance
func NewFortressSecurityMonitor(fortress *fortress.Service, config *config.Config) *FortressSecurityMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	metrics := initializeSecurityMetrics()
	alertManager := NewSecurityAlertManager()
	threatIntel := NewThreatIntelligence()
	logger := NewSecurityLogger()
	
	return &FortressSecurityMonitor{
		fortress:     fortress,
		config:       config,
		alertManager: alertManager,
		metrics:      metrics,
		threatIntel:  threatIntel,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		running:      false,
	}
}

// Start begins the security monitoring process
func (fsm *FortressSecurityMonitor) Start() error {
	fsm.mutex.Lock()
	defer fsm.mutex.Unlock()
	
	if fsm.running {
		return fmt.Errorf("security monitor already running")
	}
	
	fsm.logger.Info("Starting Fortress Security Monitor")
	
	// Start monitoring goroutines
	go fsm.monitorSecurityEvents()
	go fsm.monitorPerformanceMetrics()
	go fsm.monitorThreatIntelligence()
	go fsm.processSecurityAlerts()
	go fsm.generateComplianceReports()
	go fsm.healthCheck()
	
	fsm.running = true
	fsm.logger.Info("Fortress Security Monitor started successfully")
	
	return nil
}

// Stop stops the security monitoring process
func (fsm *FortressSecurityMonitor) Stop() error {
	fsm.mutex.Lock()
	defer fsm.mutex.Unlock()
	
	if !fsm.running {
		return fmt.Errorf("security monitor not running")
	}
	
	fsm.logger.Info("Stopping Fortress Security Monitor")
	fsm.cancel()
	fsm.running = false
	
	return nil
}

// monitorSecurityEvents monitors for security events and threats
func (fsm *FortressSecurityMonitor) monitorSecurityEvents() {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	
	fsm.logger.Info("Security event monitoring started")
	
	for {
		select {
		case <-fsm.ctx.Done():
			fsm.logger.Info("Security event monitoring stopped")
			return
		case <-ticker.C:
			fsm.checkSecurityThreats()
		}
	}
}

// checkSecurityThreats checks for various security threats
func (fsm *FortressSecurityMonitor) checkSecurityThreats() {
	// Check for SQL injection attempts
	fsm.checkSQLInjectionAttempts()
	
	// Check for XSS attempts
	fsm.checkXSSAttempts()
	
	// Check for authentication anomalies
	fsm.checkAuthenticationAnomalies()
	
	// Check for rate limit violations
	fsm.checkRateLimitViolations()
	
	// Check for unauthorized access attempts
	fsm.checkUnauthorizedAccess()
	
	// Check threat intelligence indicators
	fsm.checkThreatIntelligenceIndicators()
}

// checkSQLInjectionAttempts monitors for SQL injection attempts
func (fsm *FortressSecurityMonitor) checkSQLInjectionAttempts() {
	// This would integrate with application logs or real-time monitoring
	// For demonstration, we'll simulate detection logic
	
	sqlInjectionPatterns := []string{
		"' OR 1=1 --",
		"'; DROP TABLE",
		"' UNION SELECT",
		"' AND 1=1 --",
	}
	
	// In a real implementation, this would analyze incoming requests
	// and log entries for SQL injection patterns
	for _, pattern := range sqlInjectionPatterns {
		if fsm.detectPattern("sql_injection", pattern) {
			fsm.metrics.SQLInjectionAttempts.Inc()
			fsm.generateSecurityAlert("SQL Injection Attempt", "HIGH", map[string]interface{}{
				"pattern":   pattern,
				"source":    "request_analysis",
				"timestamp": time.Now(),
			})
		}
	}
}

// checkXSSAttempts monitors for Cross-Site Scripting attempts
func (fsm *FortressSecurityMonitor) checkXSSAttempts() {
	xssPatterns := []string{
		"<script>",
		"javascript:",
		"onerror=",
		"onload=",
	}
	
	for _, pattern := range xssPatterns {
		if fsm.detectPattern("xss", pattern) {
			fsm.metrics.XSSAttempts.Inc()
			fsm.generateSecurityAlert("XSS Attempt", "MEDIUM", map[string]interface{}{
				"pattern":   pattern,
				"source":    "request_analysis",
				"timestamp": time.Now(),
			})
		}
	}
}

// checkAuthenticationAnomalies monitors for authentication anomalies
func (fsm *FortressSecurityMonitor) checkAuthenticationAnomalies() {
	// Check for brute force attacks
	if fsm.detectBruteForceAttempt() {
		fsm.metrics.AuthenticationFailures.Inc()
		fsm.generateSecurityAlert("Brute Force Attack", "HIGH", map[string]interface{}{
			"type":      "brute_force",
			"source":    "authentication_monitor",
			"timestamp": time.Now(),
		})
	}
	
	// Check for credential stuffing
	if fsm.detectCredentialStuffing() {
		fsm.generateSecurityAlert("Credential Stuffing", "HIGH", map[string]interface{}{
			"type":      "credential_stuffing",
			"source":    "authentication_monitor",
			"timestamp": time.Now(),
		})
	}
}

// checkRateLimitViolations monitors for rate limit violations
func (fsm *FortressSecurityMonitor) checkRateLimitViolations() {
	// This would integrate with rate limiting system
	if fsm.detectRateLimitViolation() {
		fsm.metrics.RateLimitViolations.Inc()
		fsm.generateSecurityAlert("Rate Limit Violation", "MEDIUM", map[string]interface{}{
			"type":      "rate_limit",
			"source":    "rate_limiter",
			"timestamp": time.Now(),
		})
	}
}

// checkUnauthorizedAccess monitors for unauthorized access attempts
func (fsm *FortressSecurityMonitor) checkUnauthorizedAccess() {
	unauthorizedPatterns := []string{
		"/admin",
		"/debug",
		"/.env",
		"/config",
	}
	
	for _, pattern := range unauthorizedPatterns {
		if fsm.detectUnauthorizedAccess(pattern) {
			fsm.metrics.UnauthorizedAccess.Inc()
			fsm.generateSecurityAlert("Unauthorized Access Attempt", "HIGH", map[string]interface{}{
				"endpoint":  pattern,
				"source":    "access_monitor",
				"timestamp": time.Now(),
			})
		}
	}
}

// checkThreatIntelligenceIndicators checks against threat intelligence indicators
func (fsm *FortressSecurityMonitor) checkThreatIntelligenceIndicators() {
	fsm.threatIntel.mutex.RLock()
	indicators := fsm.threatIntel.indicators
	fsm.threatIntel.mutex.RUnlock()
	
	for _, indicator := range indicators {
		if fsm.matchThreatIndicator(indicator) {
			fsm.metrics.ThreatDetections.Inc()
			fsm.generateSecurityAlert("Threat Intelligence Match", "HIGH", map[string]interface{}{
				"indicator_type": indicator.Type,
				"indicator_value": indicator.Value,
				"confidence": indicator.Confidence,
				"source": indicator.Source,
				"timestamp": time.Now(),
			})
		}
	}
}

// monitorPerformanceMetrics monitors performance-related security metrics
func (fsm *FortressSecurityMonitor) monitorPerformanceMetrics() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	fsm.logger.Info("Performance metrics monitoring started")
	
	for {
		select {
		case <-fsm.ctx.Done():
			fsm.logger.Info("Performance metrics monitoring stopped")
			return
		case <-ticker.C:
			fsm.collectPerformanceMetrics()
		}
	}
}

// collectPerformanceMetrics collects security-related performance metrics
func (fsm *FortressSecurityMonitor) collectPerformanceMetrics() {
	// Collect memory usage metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Check for potential DoS conditions
	if memStats.HeapInuse > 1024*1024*1024 { // 1GB
		fsm.generateSecurityAlert("High Memory Usage", "MEDIUM", map[string]interface{}{
			"heap_usage": memStats.HeapInuse,
			"source":     "performance_monitor",
			"timestamp":  time.Now(),
		})
	}
	
	// Check for goroutine leaks
	goroutines := runtime.NumGoroutine()
	if goroutines > 1000 {
		fsm.generateSecurityAlert("Potential Goroutine Leak", "MEDIUM", map[string]interface{}{
			"goroutine_count": goroutines,
			"source":          "performance_monitor",
			"timestamp":       time.Now(),
		})
	}
}

// monitorThreatIntelligence updates threat intelligence data
func (fsm *FortressSecurityMonitor) monitorThreatIntelligence() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	fsm.logger.Info("Threat intelligence monitoring started")
	
	for {
		select {
		case <-fsm.ctx.Done():
			fsm.logger.Info("Threat intelligence monitoring stopped")
			return
		case <-ticker.C:
			fsm.updateThreatIntelligence()
		}
	}
}

// updateThreatIntelligence updates threat intelligence indicators
func (fsm *FortressSecurityMonitor) updateThreatIntelligence() {
	fsm.threatIntel.mutex.Lock()
	defer fsm.threatIntel.mutex.Unlock()
	
	// In a real implementation, this would fetch from threat intelligence sources
	// For demonstration, we'll add some sample indicators
	newIndicators := []ThreatIndicator{
		{
			Type:       "ip",
			Value:      "192.168.1.100",
			Confidence: 0.8,
			Source:     "threat_feed",
			Tags:       []string{"malware", "c2"},
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
		{
			Type:       "domain",
			Value:      "malicious-domain.com",
			Confidence: 0.9,
			Source:     "threat_feed",
			Tags:       []string{"phishing"},
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	
	fsm.threatIntel.indicators = append(fsm.threatIntel.indicators, newIndicators...)
	fsm.threatIntel.lastUpdate = time.Now()
	
	fsm.logger.Info(fmt.Sprintf("Updated threat intelligence with %d new indicators", len(newIndicators)))
}

// processSecurityAlerts processes and distributes security alerts
func (fsm *FortressSecurityMonitor) processSecurityAlerts() {
	fsm.logger.Info("Security alert processing started")
	
	for {
		select {
		case <-fsm.ctx.Done():
			fsm.logger.Info("Security alert processing stopped")
			return
		case alert := <-fsm.alertManager.channels["main"]:
			fsm.handleSecurityAlert(alert)
		}
	}
}

// generateComplianceReports generates periodic compliance reports
func (fsm *FortressSecurityMonitor) generateComplianceReports() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	
	fsm.logger.Info("Compliance reporting started")
	
	for {
		select {
		case <-fsm.ctx.Done():
			fsm.logger.Info("Compliance reporting stopped")
			return
		case <-ticker.C:
			fsm.generateDailyComplianceReport()
		}
	}
}

// healthCheck performs periodic health checks
func (fsm *FortressSecurityMonitor) healthCheck() {
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	
	for {
		select {
		case <-fsm.ctx.Done():
			return
		case <-ticker.C:
			fsm.performHealthCheck()
		}
	}
}

// generateSecurityAlert generates a security alert
func (fsm *FortressSecurityMonitor) generateSecurityAlert(alertType, severity string, details map[string]interface{}) {
	alert := SecurityAlert{
		ID:          generateAlertID(),
		Type:        alertType,
		Severity:    severity,
		Source:      "fortress_monitor",
		Description: fmt.Sprintf("Security alert: %s", alertType),
		Details:     details,
		Timestamp:   time.Now(),
		Status:      "open",
	}
	
	fsm.metrics.SecurityAlerts.Inc()
	fsm.alertManager.AddAlert(alert)
}

// handleSecurityAlert handles individual security alerts
func (fsm *FortressSecurityMonitor) handleSecurityAlert(alert SecurityAlert) {
	fsm.logger.Alert(fmt.Sprintf("Security Alert [%s]: %s", alert.Severity, alert.Type))
	
	// Log the alert
	alertData, _ := json.Marshal(alert)
	fsm.logger.Security(string(alertData))
	
	// Apply alert rules
	for _, rule := range fsm.alertManager.rules {
		if fsm.evaluateAlertRule(rule, alert) {
			fsm.executeAlertAction(rule, alert)
		}
	}
	
	// Update metrics based on alert
	switch alert.Type {
	case "SQL Injection Attempt":
		fsm.metrics.SQLInjectionAttempts.Inc()
	case "XSS Attempt":
		fsm.metrics.XSSAttempts.Inc()
	case "Brute Force Attack":
		fsm.metrics.AuthenticationFailures.Inc()
	}
}

// generateDailyComplianceReport generates daily compliance reports
func (fsm *FortressSecurityMonitor) generateDailyComplianceReport() {
	fsm.logger.Info("Generating daily compliance report")
	
	report := map[string]interface{}{
		"date":                  time.Now().Format("2006-01-02"),
		"security_alerts_count": fsm.getAlertCount(),
		"vulnerability_count":   fsm.getVulnerabilityCount(),
		"compliance_score":      fsm.calculateComplianceScore(),
		"incidents_resolved":    fsm.getResolvedIncidentCount(),
		"security_coverage":     fsm.getSecurityTestCoverage(),
	}
	
	// Update compliance score metric
	score := fsm.calculateComplianceScore()
	fsm.metrics.ComplianceScore.Set(score)
	
	// Save report
	reportData, _ := json.MarshalIndent(report, "", "  ")
	filename := fmt.Sprintf("compliance_report_%s.json", time.Now().Format("2006-01-02"))
	os.WriteFile(filename, reportData, 0644)
	
	fsm.logger.Info(fmt.Sprintf("Daily compliance report saved: %s", filename))
}

// performHealthCheck performs system health checks
func (fsm *FortressSecurityMonitor) performHealthCheck() {
	// Check if monitoring components are healthy
	healthy := true
	
	if !fsm.alertManager.IsHealthy() {
		healthy = false
		fsm.logger.Error("Alert manager health check failed")
	}
	
	if !fsm.threatIntel.IsHealthy() {
		healthy = false
		fsm.logger.Error("Threat intelligence health check failed")
	}
	
	if healthy {
		fsm.logger.Debug("Security monitor health check passed")
	} else {
		fsm.generateSecurityAlert("Monitor Health Issue", "MEDIUM", map[string]interface{}{
			"source":    "health_check",
			"timestamp": time.Now(),
		})
	}
}

// Helper methods for threat detection (simplified implementations)

func (fsm *FortressSecurityMonitor) detectPattern(patternType, pattern string) bool {
	// This would integrate with actual request/log analysis
	// Simplified implementation for demonstration
	return false // Most patterns won't be detected in normal operation
}

func (fsm *FortressSecurityMonitor) detectBruteForceAttempt() bool {
	// This would analyze authentication logs for patterns
	return false
}

func (fsm *FortressSecurityMonitor) detectCredentialStuffing() bool {
	// This would detect credential stuffing patterns
	return false
}

func (fsm *FortressSecurityMonitor) detectRateLimitViolation() bool {
	// This would integrate with rate limiting system
	return false
}

func (fsm *FortressSecurityMonitor) detectUnauthorizedAccess(pattern string) bool {
	// This would analyze access logs
	return false
}

func (fsm *FortressSecurityMonitor) matchThreatIndicator(indicator ThreatIndicator) bool {
	// This would match against actual network traffic/logs
	return false
}

func (fsm *FortressSecurityMonitor) evaluateAlertRule(rule AlertRule, alert SecurityAlert) bool {
	// Simplified rule evaluation
	if !rule.Enabled {
		return false
	}
	
	// Basic severity matching
	return rule.Condition == alert.Type || rule.Condition == alert.Severity
}

func (fsm *FortressSecurityMonitor) executeAlertAction(rule AlertRule, alert SecurityAlert) {
	fsm.logger.Info(fmt.Sprintf("Executing alert action: %s for alert: %s", rule.Action, alert.Type))
	
	switch rule.Action {
	case "immediate_notification":
		// Send immediate notification
		fsm.sendNotification(rule.Recipients, alert)
	case "alert_and_investigate":
		// Trigger investigation workflow
		fsm.triggerInvestigation(alert)
	case "block_and_alert":
		// Block source and send alert
		fsm.blockSource(alert)
		fsm.sendNotification(rule.Recipients, alert)
	}
}

func (fsm *FortressSecurityMonitor) sendNotification(recipients []string, alert SecurityAlert) {
	for _, recipient := range recipients {
		fsm.logger.Info(fmt.Sprintf("Sending notification to %s for alert: %s", recipient, alert.Type))
		// Implementation would send actual notifications (email, Slack, etc.)
	}
}

func (fsm *FortressSecurityMonitor) triggerInvestigation(alert SecurityAlert) {
	fsm.logger.Info(fmt.Sprintf("Triggering investigation for alert: %s", alert.Type))
	// Implementation would trigger investigation workflow
}

func (fsm *FortressSecurityMonitor) blockSource(alert SecurityAlert) {
	fsm.logger.Info(fmt.Sprintf("Blocking source for alert: %s", alert.Type))
	// Implementation would block IP/user/session
}

// Utility methods

func (fsm *FortressSecurityMonitor) getAlertCount() int {
	fsm.alertManager.mutex.RLock()
	defer fsm.alertManager.mutex.RUnlock()
	return len(fsm.alertManager.alerts)
}

func (fsm *FortressSecurityMonitor) getVulnerabilityCount() int {
	// This would query vulnerability database
	return 0
}

func (fsm *FortressSecurityMonitor) calculateComplianceScore() float64 {
	// Calculate compliance score based on various factors
	baseScore := 100.0
	
	// Deduct points for active alerts
	alertCount := float64(fsm.getAlertCount())
	baseScore -= alertCount * 2.0
	
	// Ensure score doesn't go below 0
	if baseScore < 0 {
		baseScore = 0
	}
	
	return baseScore
}

func (fsm *FortressSecurityMonitor) getResolvedIncidentCount() int {
	// This would query incident tracking system
	return 0
}

func (fsm *FortressSecurityMonitor) getSecurityTestCoverage() float64 {
	// This would calculate security test coverage
	return 95.0
}

// SecurityAlertManager implementation

func NewSecurityAlertManager() *SecurityAlertManager {
	return &SecurityAlertManager{
		alerts:   make([]SecurityAlert, 0),
		channels: map[string]chan SecurityAlert{
			"main": make(chan SecurityAlert, 1000),
		},
		rules:  initializeAlertRules(),
		logger: NewSecurityLogger(),
	}
}

func (sam *SecurityAlertManager) AddAlert(alert SecurityAlert) {
	sam.mutex.Lock()
	defer sam.mutex.Unlock()
	
	sam.alerts = append(sam.alerts, alert)
	
	// Send to processing channel
	select {
	case sam.channels["main"] <- alert:
	default:
		sam.logger.Error("Alert channel full, dropping alert")
	}
}

func (sam *SecurityAlertManager) IsHealthy() bool {
	sam.mutex.RLock()
	defer sam.mutex.RUnlock()
	
	// Check if channels are not blocked
	return len(sam.channels["main"]) < cap(sam.channels["main"])/2
}

// ThreatIntelligence implementation

func NewThreatIntelligence() *ThreatIntelligence {
	return &ThreatIntelligence{
		sources:    make(map[string]ThreatSource),
		indicators: make([]ThreatIndicator, 0),
	}
}

func (ti *ThreatIntelligence) IsHealthy() bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	
	// Check if threat intelligence was updated recently
	return time.Since(ti.lastUpdate) < 24*time.Hour
}

// SecurityLogger implementation

func NewSecurityLogger() *SecurityLogger {
	logFile, err := os.OpenFile("fortress_security.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Failed to open security log file")
	}
	
	logger := log.New(logFile, "[FORTRESS] ", log.LstdFlags|log.Lshortfile)
	
	return &SecurityLogger{
		logger: logger,
		file:   logFile,
	}
}

func (sl *SecurityLogger) Info(msg string) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.logger.Printf("[INFO] %s", msg)
}

func (sl *SecurityLogger) Error(msg string) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.logger.Printf("[ERROR] %s", msg)
}

func (sl *SecurityLogger) Alert(msg string) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.logger.Printf("[ALERT] %s", msg)
}

func (sl *SecurityLogger) Security(msg string) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.logger.Printf("[SECURITY] %s", msg)
}

func (sl *SecurityLogger) Debug(msg string) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.logger.Printf("[DEBUG] %s", msg)
}

// Initialize functions

func initializeSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		VulnerabilityCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "fortress_vulnerabilities_total",
			Help: "Total number of active vulnerabilities",
		}),
		SecurityTestCoverage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "fortress_security_test_coverage",
			Help: "Percentage of code covered by security tests",
		}),
		AuthenticationFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_auth_failures_total",
			Help: "Total number of authentication failures",
		}),
		APISecurityViolations: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_api_security_violations_total",
			Help: "Total number of API security violations",
		}),
		SQLInjectionAttempts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_sql_injection_attempts_total",
			Help: "Total number of SQL injection attempts",
		}),
		XSSAttempts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_xss_attempts_total",
			Help: "Total number of XSS attempts",
		}),
		RateLimitViolations: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_rate_limit_violations_total",
			Help: "Total number of rate limit violations",
		}),
		UnauthorizedAccess: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_unauthorized_access_total",
			Help: "Total number of unauthorized access attempts",
		}),
		ThreatDetections: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_threat_detections_total",
			Help: "Total number of threat detections",
		}),
		ComplianceScore: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "fortress_compliance_score",
			Help: "Current compliance score (0-100)",
		}),
		SecurityAlerts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "fortress_security_alerts_total",
			Help: "Total number of security alerts generated",
		}),
		ResponseTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "fortress_security_response_time_seconds",
			Help:    "Security alert response time in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}
}

func initializeAlertRules() []AlertRule {
	return []AlertRule{
		{
			ID:        "high_severity_vuln",
			Name:      "High Severity Vulnerability",
			Condition: "HIGH",
			Severity:  "HIGH",
			Action:    "immediate_notification",
			Enabled:   true,
			Recipients: []string{"security-team@company.com"},
		},
		{
			ID:        "sql_injection_attempt",
			Name:      "SQL Injection Attempt",
			Condition: "SQL Injection Attempt",
			Severity:  "HIGH",
			Action:    "block_and_alert",
			Enabled:   true,
			Recipients: []string{"security-team@company.com"},
		},
		{
			ID:        "brute_force_attack",
			Name:      "Brute Force Attack",
			Condition: "Brute Force Attack",
			Severity:  "HIGH",
			Action:    "alert_and_investigate",
			Enabled:   true,
			Recipients: []string{"security-team@company.com"},
		},
	}
}

func generateAlertID() string {
	return fmt.Sprintf("ALERT-%d", time.Now().UnixNano())
}