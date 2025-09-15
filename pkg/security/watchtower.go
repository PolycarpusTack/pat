// Package security implements fortress-grade monitoring and alerting
// FORTRESS WATCHTOWER SYSTEM - Real-time security monitoring and threat detection
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// WatchtowerConfig defines fortress monitoring configuration
type WatchtowerConfig struct {
	// Alert thresholds
	RateLimitViolationThreshold    int           `json:"rate_limit_violation_threshold"`
	ValidationFailureThreshold     int           `json:"validation_failure_threshold"`
	SuspiciousActivityThreshold    int           `json:"suspicious_activity_threshold"`
	
	// Time windows for analysis
	ShortTermWindow               time.Duration `json:"short_term_window"`
	MediumTermWindow              time.Duration `json:"medium_term_window"`
	LongTermWindow                time.Duration `json:"long_term_window"`
	
	// Alert settings
	EnableEmailAlerts             bool          `json:"enable_email_alerts"`
	EnableSlackAlerts             bool          `json:"enable_slack_alerts"`
	EnableWebhookAlerts           bool          `json:"enable_webhook_alerts"`
	AlertCooldown                 time.Duration `json:"alert_cooldown"`
	
	// Monitoring settings
	MetricsRetentionPeriod        time.Duration `json:"metrics_retention_period"`
	SampleRate                    float64       `json:"sample_rate"`
	
	// Emergency settings
	EmergencyThreshold            int           `json:"emergency_threshold"`
	AutoEmergencyMode             bool          `json:"auto_emergency_mode"`
	EmergencyContacts             []string      `json:"emergency_contacts"`
	
	// Pattern detection
	EnablePatternDetection        bool          `json:"enable_pattern_detection"`
	MinPatternOccurrences         int           `json:"min_pattern_occurrences"`
	PatternTimeWindow             time.Duration `json:"pattern_time_window"`
}

// DefaultWatchtowerConfig returns fortress-grade monitoring configuration
func DefaultWatchtowerConfig() *WatchtowerConfig {
	return &WatchtowerConfig{
		RateLimitViolationThreshold:   100,
		ValidationFailureThreshold:    50,
		SuspiciousActivityThreshold:   25,
		
		ShortTermWindow:              5 * time.Minute,
		MediumTermWindow:             30 * time.Minute,
		LongTermWindow:               2 * time.Hour,
		
		EnableEmailAlerts:            true,
		EnableSlackAlerts:            false,
		EnableWebhookAlerts:          true,
		AlertCooldown:                15 * time.Minute,
		
		MetricsRetentionPeriod:       24 * time.Hour,
		SampleRate:                   1.0,
		
		EmergencyThreshold:           500,
		AutoEmergencyMode:            true,
		EmergencyContacts:            []string{},
		
		EnablePatternDetection:       true,
		MinPatternOccurrences:        10,
		PatternTimeWindow:            10 * time.Minute,
	}
}

// SecurityEvent represents a fortress security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time             `json:"timestamp"`
	Type        string                `json:"type"`
	Severity    string                `json:"severity"`
	Source      string                `json:"source"`
	IP          string                `json:"ip"`
	UserAgent   string                `json:"user_agent"`
	Endpoint    string                `json:"endpoint"`
	Method      string                `json:"method"`
	Details     map[string]interface{} `json:"details"`
	ThreatLevel string                `json:"threat_level"`
	Action      string                `json:"action"`
	GeoInfo     *GeoInfo              `json:"geo_info,omitempty"`
}

// SecurityAlert represents a fortress security alert
type SecurityAlert struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time             `json:"timestamp"`
	Type          string                `json:"type"`
	Severity      string                `json:"severity"`
	Title         string                `json:"title"`
	Description   string                `json:"description"`
	Events        []SecurityEvent       `json:"events"`
	Metrics       map[string]interface{} `json:"metrics"`
	Recommended   []string              `json:"recommended_actions"`
	Acknowledged  bool                  `json:"acknowledged"`
	ResolvedAt    *time.Time            `json:"resolved_at,omitempty"`
}

// SecurityMetrics represents fortress security metrics
type SecurityMetrics struct {
	Timestamp           time.Time `json:"timestamp"`
	TotalRequests       int64     `json:"total_requests"`
	BlockedRequests     int64     `json:"blocked_requests"`
	RateLimitViolations int64     `json:"rate_limit_violations"`
	ValidationFailures  int64     `json:"validation_failures"`
	ThreatsByLevel      map[string]int64 `json:"threats_by_level"`
	TopAttackerIPs      []IPStats `json:"top_attacker_ips"`
	TopTargetEndpoints  []EndpointStats `json:"top_target_endpoints"`
	PatternDetections   int64     `json:"pattern_detections"`
	EmergencyActivations int64    `json:"emergency_activations"`
}

// IPStats represents statistics for an IP address
type IPStats struct {
	IP          string `json:"ip"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
	ThreatLevel string `json:"threat_level"`
	Country     string `json:"country"`
}

// EndpointStats represents statistics for an endpoint
type EndpointStats struct {
	Endpoint    string `json:"endpoint"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
	AvgResponse float64 `json:"avg_response_time"`
}

// PatternDetection represents a detected attack pattern
type PatternDetection struct {
	ID          string      `json:"id"`
	Timestamp   time.Time   `json:"timestamp"`
	Pattern     string      `json:"pattern"`
	Occurrences int         `json:"occurrences"`
	IPs         []string    `json:"ips"`
	Endpoints   []string    `json:"endpoints"`
	ThreatLevel string      `json:"threat_level"`
	Confidence  float64     `json:"confidence"`
}

// AlertChannel interface for sending alerts
type AlertChannel interface {
	SendAlert(alert *SecurityAlert) error
}

// FortressWatchtower implements comprehensive security monitoring
type FortressWatchtower struct {
	config       *WatchtowerConfig
	logger       *zap.Logger
	events       chan SecurityEvent
	alerts       chan SecurityAlert
	metrics      *SecurityMetrics
	patterns     map[string]*PatternDetection
	alertHistory map[string]time.Time
	channels     []AlertChannel
	
	// Thread-safe access
	mutex        sync.RWMutex
	patternMutex sync.RWMutex
	alertMutex   sync.RWMutex
	
	// Control
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewFortressWatchtower creates a new fortress security monitoring system
func NewFortressWatchtower(config *WatchtowerConfig, logger *zap.Logger) *FortressWatchtower {
	if config == nil {
		config = DefaultWatchtowerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	watchtower := &FortressWatchtower{
		config:       config,
		logger:       logger,
		events:       make(chan SecurityEvent, 10000),
		alerts:       make(chan SecurityAlert, 1000),
		metrics:      &SecurityMetrics{
			Timestamp:      time.Now(),
			ThreatsByLevel: make(map[string]int64),
		},
		patterns:     make(map[string]*PatternDetection),
		alertHistory: make(map[string]time.Time),
		channels:     make([]AlertChannel, 0),
		ctx:          ctx,
		cancel:       cancel,
	}
	
	return watchtower
}

// Start begins fortress monitoring operations
func (fw *FortressWatchtower) Start() error {
	fw.logger.Info("Starting Fortress Watchtower monitoring system")
	
	// Start event processing goroutine
	fw.wg.Add(1)
	go fw.processEvents()
	
	// Start alert processing goroutine
	fw.wg.Add(1)
	go fw.processAlerts()
	
	// Start metrics collection goroutine
	fw.wg.Add(1)
	go fw.collectMetrics()
	
	// Start pattern detection goroutine
	if fw.config.EnablePatternDetection {
		fw.wg.Add(1)
		go fw.detectPatterns()
	}
	
	// Start cleanup goroutine
	fw.wg.Add(1)
	go fw.cleanup()
	
	return nil
}

// Stop gracefully shuts down fortress monitoring
func (fw *FortressWatchtower) Stop() error {
	fw.logger.Info("Stopping Fortress Watchtower monitoring system")
	
	fw.cancel()
	
	// Close channels to signal shutdown
	close(fw.events)
	close(fw.alerts)
	
	// Wait for goroutines to finish
	fw.wg.Wait()
	
	return nil
}

// RecordEvent records a fortress security event
func (fw *FortressWatchtower) RecordEvent(event SecurityEvent) {
	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	// Generate ID if not provided
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%s", event.Timestamp.UnixNano(), event.Type)
	}
	
	// Send to processing channel (non-blocking)
	select {
	case fw.events <- event:
		// Event queued successfully
	default:
		// Channel full, log warning
		fw.logger.Warn("Event queue full, dropping event", 
			zap.String("event_id", event.ID),
			zap.String("event_type", event.Type))
	}
}

// processEvents processes security events and triggers alerts
func (fw *FortressWatchtower) processEvents() {
	defer fw.wg.Done()
	
	eventBuffer := make([]SecurityEvent, 0, 1000)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-fw.ctx.Done():
			return
			
		case event, ok := <-fw.events:
			if !ok {
				return
			}
			
			// Add event to buffer
			eventBuffer = append(eventBuffer, event)
			
			// Update metrics
			fw.updateMetricsFromEvent(event)
			
			// Check for immediate alerts
			fw.checkImmediateAlerts(event)
			
		case <-ticker.C:
			// Process buffered events
			if len(eventBuffer) > 0 {
				fw.analyzeBatchEvents(eventBuffer)
				eventBuffer = eventBuffer[:0] // Clear buffer
			}
		}
	}
}

// processAlerts processes and sends security alerts
func (fw *FortressWatchtower) processAlerts() {
	defer fw.wg.Done()
	
	for {
		select {
		case <-fw.ctx.Done():
			return
			
		case alert, ok := <-fw.alerts:
			if !ok {
				return
			}
			
			// Check alert cooldown
			if fw.isInCooldown(alert) {
				continue
			}
			
			// Send alert through all channels
			for _, channel := range fw.channels {
				if err := channel.SendAlert(&alert); err != nil {
					fw.logger.Error("Failed to send alert", 
						zap.String("alert_id", alert.ID),
						zap.Error(err))
				}
			}
			
			// Update alert history
			fw.alertMutex.Lock()
			fw.alertHistory[alert.Type] = alert.Timestamp
			fw.alertMutex.Unlock()
			
			fw.logger.Info("Security alert sent", 
				zap.String("alert_id", alert.ID),
				zap.String("type", alert.Type),
				zap.String("severity", alert.Severity))
		}
	}
}

// collectMetrics periodically collects and aggregates security metrics
func (fw *FortressWatchtower) collectMetrics() {
	defer fw.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-fw.ctx.Done():
			return
			
		case <-ticker.C:
			fw.updateAggregateMetrics()
		}
	}
}

// detectPatterns detects attack patterns in security events
func (fw *FortressWatchtower) detectPatterns() {
	defer fw.wg.Done()
	
	ticker := time.NewTicker(fw.config.PatternTimeWindow)
	defer ticker.Stop()
	
	for {
		select {
		case <-fw.ctx.Done():
			return
			
		case <-ticker.C:
			fw.analyzePatterns()
		}
	}
}

// cleanup performs periodic cleanup of old data
func (fw *FortressWatchtower) cleanup() {
	defer fw.wg.Done()
	
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-fw.ctx.Done():
			return
			
		case <-ticker.C:
			fw.performCleanup()
		}
	}
}

// updateMetricsFromEvent updates metrics based on a security event
func (fw *FortressWatchtower) updateMetricsFromEvent(event SecurityEvent) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	
	fw.metrics.TotalRequests++
	
	if event.Action == "blocked" {
		fw.metrics.BlockedRequests++
	}
	
	switch event.Type {
	case "rate_limit_violation":
		fw.metrics.RateLimitViolations++
	case "validation_failure":
		fw.metrics.ValidationFailures++
	case "pattern_detection":
		fw.metrics.PatternDetections++
	case "emergency_activation":
		fw.metrics.EmergencyActivations++
	}
	
	// Update threat level counts
	if event.ThreatLevel != "" {
		fw.metrics.ThreatsByLevel[event.ThreatLevel]++
	}
}

// checkImmediateAlerts checks if an event should trigger an immediate alert
func (fw *FortressWatchtower) checkImmediateAlerts(event SecurityEvent) {
	switch event.Severity {
	case "CRITICAL":
		fw.createAlert("CRITICAL_SECURITY_EVENT", "CRITICAL", 
			"Critical security event detected",
			fmt.Sprintf("Critical security event of type %s detected from IP %s", event.Type, event.IP),
			[]SecurityEvent{event})
			
	case "HIGH":
		if event.Type == "honeypot_access" || event.Type == "automation_detected" {
			fw.createAlert("HIGH_THREAT_DETECTED", "HIGH",
				"High threat activity detected",
				fmt.Sprintf("High threat activity detected: %s from IP %s", event.Type, event.IP),
				[]SecurityEvent{event})
		}
	}
}

// analyzeBatchEvents analyzes a batch of events for patterns and thresholds
func (fw *FortressWatchtower) analyzeBatchEvents(events []SecurityEvent) {
	// Count events by type and IP
	eventCounts := make(map[string]int)
	ipCounts := make(map[string]int)
	
	for _, event := range events {
		eventCounts[event.Type]++
		if event.IP != "" {
			ipCounts[event.IP]++
		}
	}
	
	// Check thresholds
	for eventType, count := range eventCounts {
		threshold := fw.getThresholdForEventType(eventType)
		if count >= threshold {
			fw.createAlert("THRESHOLD_EXCEEDED", "HIGH",
				"Security event threshold exceeded",
				fmt.Sprintf("Event type %s exceeded threshold: %d >= %d", eventType, count, threshold),
				events)
		}
	}
	
	// Check for concentrated attacks from single IP
	for ip, count := range ipCounts {
		if count >= 50 { // Configurable threshold
			ipEvents := make([]SecurityEvent, 0)
			for _, event := range events {
				if event.IP == ip {
					ipEvents = append(ipEvents, event)
				}
			}
			
			fw.createAlert("CONCENTRATED_ATTACK", "HIGH",
				"Concentrated attack detected",
				fmt.Sprintf("Concentrated attack from IP %s: %d events", ip, count),
				ipEvents)
		}
	}
}

// analyzePatterns analyzes events for attack patterns
func (fw *FortressWatchtower) analyzePatterns() {
	fw.patternMutex.Lock()
	defer fw.patternMutex.Unlock()
	
	// Simple pattern analysis - in a real implementation, this would be more sophisticated
	cutoff := time.Now().Add(-fw.config.PatternTimeWindow)
	
	// Clean up old patterns
	for id, pattern := range fw.patterns {
		if pattern.Timestamp.Before(cutoff) {
			delete(fw.patterns, id)
		}
	}
	
	// Analyze current patterns for alerts
	for _, pattern := range fw.patterns {
		if pattern.Occurrences >= fw.config.MinPatternOccurrences && pattern.Confidence > 0.7 {
			fw.createAlert("ATTACK_PATTERN_DETECTED", "HIGH",
				"Attack pattern detected",
				fmt.Sprintf("Pattern %s detected %d times with %f confidence", 
					pattern.Pattern, pattern.Occurrences, pattern.Confidence),
				[]SecurityEvent{})
		}
	}
}

// performCleanup cleans up old data to prevent memory bloat
func (fw *FortressWatchtower) performCleanup() {
	cutoff := time.Now().Add(-fw.config.MetricsRetentionPeriod)
	
	// Clean up alert history
	fw.alertMutex.Lock()
	for alertType, timestamp := range fw.alertHistory {
		if timestamp.Before(cutoff) {
			delete(fw.alertHistory, alertType)
		}
	}
	fw.alertMutex.Unlock()
	
	fw.logger.Debug("Performed watchtower cleanup")
}

// createAlert creates and queues a security alert
func (fw *FortressWatchtower) createAlert(alertType, severity, title, description string, events []SecurityEvent) {
	alert := SecurityAlert{
		ID:          fmt.Sprintf("%d-%s", time.Now().UnixNano(), alertType),
		Timestamp:   time.Now(),
		Type:        alertType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Events:      events,
		Metrics:     fw.getRelevantMetrics(),
		Recommended: fw.getRecommendedActions(alertType),
	}
	
	// Queue alert (non-blocking)
	select {
	case fw.alerts <- alert:
		// Alert queued successfully
	default:
		// Alert queue full
		fw.logger.Warn("Alert queue full, dropping alert", 
			zap.String("alert_type", alertType))
	}
}

// isInCooldown checks if an alert type is in cooldown period
func (fw *FortressWatchtower) isInCooldown(alert SecurityAlert) bool {
	fw.alertMutex.RLock()
	defer fw.alertMutex.RUnlock()
	
	if lastAlert, exists := fw.alertHistory[alert.Type]; exists {
		return time.Since(lastAlert) < fw.config.AlertCooldown
	}
	
	return false
}

// getThresholdForEventType returns the threshold for a specific event type
func (fw *FortressWatchtower) getThresholdForEventType(eventType string) int {
	switch eventType {
	case "rate_limit_violation":
		return fw.config.RateLimitViolationThreshold
	case "validation_failure":
		return fw.config.ValidationFailureThreshold
	default:
		return fw.config.SuspiciousActivityThreshold
	}
}

// getRelevantMetrics returns relevant metrics for an alert
func (fw *FortressWatchtower) getRelevantMetrics() map[string]interface{} {
	fw.mutex.RLock()
	defer fw.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_requests":        fw.metrics.TotalRequests,
		"blocked_requests":      fw.metrics.BlockedRequests,
		"rate_limit_violations": fw.metrics.RateLimitViolations,
		"validation_failures":   fw.metrics.ValidationFailures,
		"threats_by_level":      fw.metrics.ThreatsByLevel,
	}
}

// getRecommendedActions returns recommended actions for an alert type
func (fw *FortressWatchtower) getRecommendedActions(alertType string) []string {
	switch alertType {
	case "CRITICAL_SECURITY_EVENT":
		return []string{
			"Immediately investigate the source IP",
			"Block the IP address if confirmed malicious",
			"Review security logs for related activity",
			"Consider activating emergency mode",
		}
	case "THRESHOLD_EXCEEDED":
		return []string{
			"Review rate limiting configuration",
			"Analyze traffic patterns for anomalies",
			"Consider temporary rate limit reduction",
			"Monitor for distributed attacks",
		}
	case "CONCENTRATED_ATTACK":
		return []string{
			"Block the attacking IP address",
			"Review firewall rules",
			"Analyze attack patterns",
			"Update security signatures",
		}
	case "ATTACK_PATTERN_DETECTED":
		return []string{
			"Update pattern detection rules",
			"Block known attack signatures",
			"Review application security",
			"Consider WAF rule updates",
		}
	default:
		return []string{
			"Investigate the security event",
			"Review relevant logs",
			"Update security policies if needed",
		}
	}
}

// updateAggregateMetrics updates aggregate security metrics
func (fw *FortressWatchtower) updateAggregateMetrics() {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()
	
	fw.metrics.Timestamp = time.Now()
	
	// Additional metric calculations would go here
	// For now, we just update the timestamp
}

// AddAlertChannel adds an alert channel for notifications
func (fw *FortressWatchtower) AddAlertChannel(channel AlertChannel) {
	fw.channels = append(fw.channels, channel)
}

// GetMetrics returns current security metrics
func (fw *FortressWatchtower) GetMetrics() *SecurityMetrics {
	fw.mutex.RLock()
	defer fw.mutex.RUnlock()
	
	// Return a copy to prevent concurrent access issues
	metrics := &SecurityMetrics{
		Timestamp:           fw.metrics.Timestamp,
		TotalRequests:       fw.metrics.TotalRequests,
		BlockedRequests:     fw.metrics.BlockedRequests,
		RateLimitViolations: fw.metrics.RateLimitViolations,
		ValidationFailures:  fw.metrics.ValidationFailures,
		ThreatsByLevel:      make(map[string]int64),
		PatternDetections:   fw.metrics.PatternDetections,
		EmergencyActivations: fw.metrics.EmergencyActivations,
	}
	
	// Copy threats by level
	for level, count := range fw.metrics.ThreatsByLevel {
		metrics.ThreatsByLevel[level] = count
	}
	
	return metrics
}

// GetConfig returns the current watchtower configuration
func (fw *FortressWatchtower) GetConfig() *WatchtowerConfig {
	return fw.config
}

// UpdateConfig updates the watchtower configuration
func (fw *FortressWatchtower) UpdateConfig(config *WatchtowerConfig) {
	fw.config = config
	fw.logger.Info("Fortress watchtower configuration updated")
}

// TriggerEmergencyMode triggers emergency fortress protocols
func (fw *FortressWatchtower) TriggerEmergencyMode(reason string) {
	fw.logger.Warn("Fortress emergency mode triggered", zap.String("reason", reason))
	
	event := SecurityEvent{
		Timestamp:   time.Now(),
		Type:        "emergency_activation",
		Severity:    "CRITICAL",
		Source:      "watchtower",
		ThreatLevel: "CRITICAL",
		Action:      "emergency_mode_activated",
		Details: map[string]interface{}{
			"reason": reason,
		},
	}
	
	fw.RecordEvent(event)
	
	fw.createAlert("EMERGENCY_MODE_ACTIVATED", "CRITICAL",
		"Fortress Emergency Mode Activated",
		"Emergency mode has been activated: "+reason,
		[]SecurityEvent{event})
}