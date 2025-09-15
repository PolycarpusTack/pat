// Package security implements fortress-grade request security validation
// FORTRESS RAMPART SYSTEM - Advanced request security and header validation
package security

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
)

// RampartSecurityConfig defines fortress request security configuration
type RampartSecurityConfig struct {
	// Request size limits
	MaxRequestSize        int64    `json:"max_request_size"`
	MaxHeaderSize         int      `json:"max_header_size"`
	MaxHeaderCount        int      `json:"max_header_count"`
	MaxQueryParams        int      `json:"max_query_params"`
	MaxCookieSize         int      `json:"max_cookie_size"`
	
	// Header validation
	RequiredHeaders       []string `json:"required_headers"`
	ForbiddenHeaders      []string `json:"forbidden_headers"`
	AllowedMethods        []string `json:"allowed_methods"`
	AllowedContentTypes   []string `json:"allowed_content_types"`
	
	// CORS security
	AllowedOrigins        []string `json:"allowed_origins"`
	AllowCredentials      bool     `json:"allow_credentials"`
	MaxAge                int      `json:"max_age"`
	
	// Security headers enforcement
	EnforceHSTS           bool     `json:"enforce_hsts"`
	EnforceCSP            bool     `json:"enforce_csp"`
	EnforceXFrameOptions  bool     `json:"enforce_x_frame_options"`
	EnforceXContentType   bool     `json:"enforce_x_content_type"`
	
	// User agent filtering
	BlockedUserAgents     []string `json:"blocked_user_agents"`
	RequireUserAgent      bool     `json:"require_user_agent"`
	
	// Geographic restrictions
	BlockedCountries      []string `json:"blocked_countries"`
	AllowedCountries      []string `json:"allowed_countries"`
	
	// Time-based restrictions
	AllowedTimeRanges     []TimeRange `json:"allowed_time_ranges"`
	BlockedTimeRanges     []TimeRange `json:"blocked_time_ranges"`
	
	// Advanced security
	EnableHoneypots       bool     `json:"enable_honeypots"`
	DetectAutomation      bool     `json:"detect_automation"`
	RequireJavaScript     bool     `json:"require_javascript"`
}

// TimeRange defines time-based access restrictions
type TimeRange struct {
	Start    string `json:"start"`    // HH:MM format
	End      string `json:"end"`      // HH:MM format
	Timezone string `json:"timezone"` // IANA timezone
	Days     []int  `json:"days"`     // 0=Sunday, 1=Monday, etc.
}

// DefaultRampartSecurityConfig returns fortress-grade default configuration
func DefaultRampartSecurityConfig() *RampartSecurityConfig {
	return &RampartSecurityConfig{
		MaxRequestSize:       10485760, // 10MB
		MaxHeaderSize:        8192,     // 8KB per header
		MaxHeaderCount:       50,
		MaxQueryParams:       100,
		MaxCookieSize:        4096,     // 4KB
		
		RequiredHeaders:      []string{"User-Agent", "Host"},
		ForbiddenHeaders:     []string{"X-Forwarded-Proto", "X-Real-IP"},
		AllowedMethods:       []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		AllowedContentTypes:  []string{
			"application/json", "application/x-www-form-urlencoded",
			"multipart/form-data", "text/plain", "application/xml",
		},
		
		AllowedOrigins:       []string{"*"},
		AllowCredentials:     true,
		MaxAge:              86400, // 24 hours
		
		EnforceHSTS:          true,
		EnforceCSP:           true,
		EnforceXFrameOptions: true,
		EnforceXContentType:  true,
		
		BlockedUserAgents:    []string{
			"curl", "wget", "python-requests", "python-urllib",
			"bot", "crawler", "spider", "scraper",
		},
		RequireUserAgent:     true,
		
		BlockedCountries:     []string{}, // Empty = none blocked
		AllowedCountries:     []string{}, // Empty = all allowed
		
		AllowedTimeRanges:    []TimeRange{}, // Empty = always allowed
		BlockedTimeRanges:    []TimeRange{}, // Empty = none blocked
		
		EnableHoneypots:      true,
		DetectAutomation:     true,
		RequireJavaScript:    false,
	}
}

// RampartSecurityResult represents fortress security validation outcome
type RampartSecurityResult struct {
	Allowed       bool     `json:"allowed"`
	BlockReason   string   `json:"block_reason,omitempty"`
	ThreatLevel   string   `json:"threat_level"`
	Score         int      `json:"score"`
	Violations    []string `json:"violations,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"` // Security headers to add
	GeoInfo       *GeoInfo `json:"geo_info,omitempty"`
}

// GeoInfo represents geographic information about the request
type GeoInfo struct {
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	ThreatLevel string  `json:"threat_level"`
}

// FortressRampart implements comprehensive request security validation
type FortressRampart struct {
	config     *RampartSecurityConfig
	logger     *zap.Logger
	geoService GeoService
	honeypots  map[string]time.Time
}

// GeoService interface for geographic IP lookup
type GeoService interface {
	LookupIP(ip string) (*GeoInfo, error)
}

// NewFortressRampart creates a new fortress request security validator
func NewFortressRampart(config *RampartSecurityConfig, geoService GeoService, logger *zap.Logger) *FortressRampart {
	if config == nil {
		config = DefaultRampartSecurityConfig()
	}
	
	return &FortressRampart{
		config:     config,
		logger:     logger,
		geoService: geoService,
		honeypots:  make(map[string]time.Time),
	}
}

// ValidateRequest performs comprehensive fortress request security validation
func (fr *FortressRampart) ValidateRequest(r *http.Request) *RampartSecurityResult {
	result := &RampartSecurityResult{
		Allowed:     true,
		ThreatLevel: "SAFE",
		Score:       100,
		Headers:     make(map[string]string),
	}
	
	// Get client IP
	clientIP := fr.getClientIP(r)
	
	// Perform all security validations
	fr.validateRequestSize(r, result)
	fr.validateHeaders(r, result)
	fr.validateMethod(r, result)
	fr.validateContentType(r, result)
	fr.validateUserAgent(r, result)
	fr.validateOrigin(r, result)
	fr.validateTimeRestrictions(r, result)
	fr.performGeoValidation(clientIP, result)
	fr.detectAutomation(r, result)
	fr.checkHoneypots(r, result)
	
	// Set security headers
	fr.setSecurityHeaders(result)
	
	// Calculate final threat level based on score
	fr.calculateThreatLevel(result)
	
	return result
}

// validateRequestSize validates request size limits
func (fr *FortressRampart) validateRequestSize(r *http.Request, result *RampartSecurityResult) {
	// Check Content-Length if present
	if r.ContentLength > fr.config.MaxRequestSize {
		result.Allowed = false
		result.BlockReason = "Request size exceeds maximum limit"
		result.ThreatLevel = "HIGH"
		result.Score -= 50
		result.Violations = append(result.Violations, "OVERSIZED_REQUEST")
		return
	}
	
	// Check header count
	headerCount := len(r.Header)
	if headerCount > fr.config.MaxHeaderCount {
		result.Allowed = false
		result.BlockReason = "Too many headers"
		result.ThreatLevel = "MEDIUM"
		result.Score -= 30
		result.Violations = append(result.Violations, "EXCESSIVE_HEADERS")
		return
	}
	
	// Check individual header sizes
	for name, values := range r.Header {
		for _, value := range values {
			if len(name)+len(value) > fr.config.MaxHeaderSize {
				result.Allowed = false
				result.BlockReason = "Header size exceeds limit"
				result.ThreatLevel = "MEDIUM"
				result.Score -= 25
				result.Violations = append(result.Violations, "OVERSIZED_HEADER")
				return
			}
		}
	}
	
	// Check query parameter count
	params := r.URL.Query()
	if len(params) > fr.config.MaxQueryParams {
		result.Allowed = false
		result.BlockReason = "Too many query parameters"
		result.ThreatLevel = "MEDIUM"
		result.Score -= 20
		result.Violations = append(result.Violations, "EXCESSIVE_PARAMS")
		return
	}
}

// validateHeaders validates HTTP headers
func (fr *FortressRampart) validateHeaders(r *http.Request, result *RampartSecurityResult) {
	// Check required headers
	for _, required := range fr.config.RequiredHeaders {
		if r.Header.Get(required) == "" {
			result.Score -= 10
			result.Warnings = append(result.Warnings, "Missing required header: "+required)
		}
	}
	
	// Check forbidden headers
	for _, forbidden := range fr.config.ForbiddenHeaders {
		if r.Header.Get(forbidden) != "" {
			result.Allowed = false
			result.BlockReason = "Forbidden header present: " + forbidden
			result.ThreatLevel = "HIGH"
			result.Score -= 40
			result.Violations = append(result.Violations, "FORBIDDEN_HEADER")
			return
		}
	}
	
	// Validate header values for suspicious content
	for name, values := range r.Header {
		for _, value := range values {
			if fr.containsSuspiciousContent(value) {
				result.Score -= 15
				result.ThreatLevel = "MEDIUM"
				result.Warnings = append(result.Warnings, "Suspicious content in header: "+name)
			}
		}
	}
}

// validateMethod validates HTTP method
func (fr *FortressRampart) validateMethod(r *http.Request, result *RampartSecurityResult) {
	methodAllowed := false
	for _, allowed := range fr.config.AllowedMethods {
		if strings.EqualFold(r.Method, allowed) {
			methodAllowed = true
			break
		}
	}
	
	if !methodAllowed {
		result.Allowed = false
		result.BlockReason = "HTTP method not allowed: " + r.Method
		result.ThreatLevel = "MEDIUM"
		result.Score -= 30
		result.Violations = append(result.Violations, "FORBIDDEN_METHOD")
	}
}

// validateContentType validates Content-Type header
func (fr *FortressRampart) validateContentType(r *http.Request, result *RampartSecurityResult) {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return // No content type validation for these methods
	}
	
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		result.Score -= 10
		result.Warnings = append(result.Warnings, "Missing Content-Type header")
		return
	}
	
	// Extract media type (ignore parameters like charset)
	mediaType := strings.Split(contentType, ";")[0]
	mediaType = strings.TrimSpace(mediaType)
	
	typeAllowed := false
	for _, allowed := range fr.config.AllowedContentTypes {
		if strings.EqualFold(mediaType, allowed) {
			typeAllowed = true
			break
		}
	}
	
	if !typeAllowed {
		result.Allowed = false
		result.BlockReason = "Content-Type not allowed: " + mediaType
		result.ThreatLevel = "MEDIUM"
		result.Score -= 25
		result.Violations = append(result.Violations, "FORBIDDEN_CONTENT_TYPE")
	}
}

// validateUserAgent validates User-Agent header
func (fr *FortressRampart) validateUserAgent(r *http.Request, result *RampartSecurityResult) {
	userAgent := r.Header.Get("User-Agent")
	
	if fr.config.RequireUserAgent && userAgent == "" {
		result.Allowed = false
		result.BlockReason = "User-Agent header required"
		result.ThreatLevel = "HIGH"
		result.Score -= 40
		result.Violations = append(result.Violations, "MISSING_USER_AGENT")
		return
	}
	
	// Check against blocked user agents
	userAgentLower := strings.ToLower(userAgent)
	for _, blocked := range fr.config.BlockedUserAgents {
		if strings.Contains(userAgentLower, strings.ToLower(blocked)) {
			result.Allowed = false
			result.BlockReason = "Blocked user agent detected"
			result.ThreatLevel = "HIGH"
			result.Score -= 50
			result.Violations = append(result.Violations, "BLOCKED_USER_AGENT")
			return
		}
	}
	
	// Detect suspicious user agent patterns
	if fr.isSuspiciousUserAgent(userAgent) {
		result.Score -= 20
		result.ThreatLevel = "MEDIUM"
		result.Warnings = append(result.Warnings, "Suspicious user agent pattern detected")
	}
}

// validateOrigin validates Origin header for CORS
func (fr *FortressRampart) validateOrigin(r *http.Request, result *RampartSecurityResult) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return // No origin validation needed for same-origin requests
	}
	
	// Check if origin is allowed
	originAllowed := false
	for _, allowed := range fr.config.AllowedOrigins {
		if allowed == "*" || strings.EqualFold(origin, allowed) {
			originAllowed = true
			break
		}
	}
	
	if !originAllowed {
		result.Allowed = false
		result.BlockReason = "Origin not allowed: " + origin
		result.ThreatLevel = "HIGH"
		result.Score -= 40
		result.Violations = append(result.Violations, "FORBIDDEN_ORIGIN")
		return
	}
	
	// Set CORS headers if origin is allowed
	if originAllowed {
		result.Headers["Access-Control-Allow-Origin"] = origin
		if fr.config.AllowCredentials {
			result.Headers["Access-Control-Allow-Credentials"] = "true"
		}
		result.Headers["Access-Control-Max-Age"] = strconv.Itoa(fr.config.MaxAge)
	}
}

// validateTimeRestrictions validates time-based access restrictions
func (fr *FortressRampart) validateTimeRestrictions(r *http.Request, result *RampartSecurityResult) {
	now := time.Now()
	
	// Check blocked time ranges
	for _, blocked := range fr.config.BlockedTimeRanges {
		if fr.isTimeInRange(now, blocked) {
			result.Allowed = false
			result.BlockReason = "Access blocked during restricted time period"
			result.ThreatLevel = "MEDIUM"
			result.Score -= 30
			result.Violations = append(result.Violations, "TIME_RESTRICTION")
			return
		}
	}
	
	// Check allowed time ranges (if any are specified)
	if len(fr.config.AllowedTimeRanges) > 0 {
		allowed := false
		for _, allowedRange := range fr.config.AllowedTimeRanges {
			if fr.isTimeInRange(now, allowedRange) {
				allowed = true
				break
			}
		}
		
		if !allowed {
			result.Allowed = false
			result.BlockReason = "Access only allowed during specified time periods"
			result.ThreatLevel = "MEDIUM"
			result.Score -= 30
			result.Violations = append(result.Violations, "TIME_RESTRICTION")
			return
		}
	}
}

// performGeoValidation validates geographic restrictions
func (fr *FortressRampart) performGeoValidation(clientIP string, result *RampartSecurityResult) {
	if fr.geoService == nil {
		return
	}
	
	geoInfo, err := fr.geoService.LookupIP(clientIP)
	if err != nil {
		fr.logger.Debug("Failed to lookup IP geolocation", zap.String("ip", clientIP), zap.Error(err))
		result.Warnings = append(result.Warnings, "Geolocation lookup failed")
		return
	}
	
	result.GeoInfo = geoInfo
	
	// Check blocked countries
	for _, blocked := range fr.config.BlockedCountries {
		if strings.EqualFold(geoInfo.Country, blocked) {
			result.Allowed = false
			result.BlockReason = "Access blocked from country: " + geoInfo.Country
			result.ThreatLevel = "HIGH"
			result.Score -= 50
			result.Violations = append(result.Violations, "GEO_BLOCKED")
			return
		}
	}
	
	// Check allowed countries (if any are specified)
	if len(fr.config.AllowedCountries) > 0 {
		allowed := false
		for _, allowedCountry := range fr.config.AllowedCountries {
			if strings.EqualFold(geoInfo.Country, allowedCountry) {
				allowed = true
				break
			}
		}
		
		if !allowed {
			result.Allowed = false
			result.BlockReason = "Access only allowed from specified countries"
			result.ThreatLevel = "HIGH"
			result.Score -= 50
			result.Violations = append(result.Violations, "GEO_RESTRICTED")
			return
		}
	}
}

// detectAutomation detects automated requests
func (fr *FortressRampart) detectAutomation(r *http.Request, result *RampartSecurityResult) {
	if !fr.config.DetectAutomation {
		return
	}
	
	automationScore := 0
	
	// Check for missing common browser headers
	browserHeaders := []string{"Accept", "Accept-Language", "Accept-Encoding", "Connection"}
	for _, header := range browserHeaders {
		if r.Header.Get(header) == "" {
			automationScore += 10
		}
	}
	
	// Check for suspicious header ordering
	if fr.hasSuspiciousHeaderOrder(r) {
		automationScore += 15
	}
	
	// Check for missing or suspicious cookies
	if len(r.Cookies()) == 0 {
		automationScore += 10
	}
	
	// Check for suspicious request patterns
	if fr.hasSuspiciousRequestPattern(r) {
		automationScore += 20
	}
	
	if automationScore >= 30 {
		result.Score -= automationScore
		result.ThreatLevel = "MEDIUM"
		result.Warnings = append(result.Warnings, "Potential automated request detected")
		
		if automationScore >= 50 {
			result.Allowed = false
			result.BlockReason = "Automated request detected"
			result.ThreatLevel = "HIGH"
			result.Violations = append(result.Violations, "AUTOMATION_DETECTED")
		}
	}
}

// checkHoneypots checks for honeypot access attempts
func (fr *FortressRampart) checkHoneypots(r *http.Request, result *RampartSecurityResult) {
	if !fr.config.EnableHoneypots {
		return
	}
	
	// Define honeypot paths
	honeypotPaths := []string{
		"/wp-admin", "/admin", "/administrator", "/phpmyadmin",
		"/.env", "/config.php", "/backup", "/test",
		"/robots.txt", "/sitemap.xml", // Common bot targets
	}
	
	for _, path := range honeypotPaths {
		if strings.HasPrefix(r.URL.Path, path) {
			clientIP := fr.getClientIP(r)
			fr.honeypots[clientIP] = time.Now()
			
			result.Allowed = false
			result.BlockReason = "Honeypot access detected"
			result.ThreatLevel = "CRITICAL"
			result.Score -= 100
			result.Violations = append(result.Violations, "HONEYPOT_ACCESS")
			
			fr.logger.Warn("Honeypot access detected", 
				zap.String("ip", clientIP), 
				zap.String("path", r.URL.Path),
				zap.String("user_agent", r.Header.Get("User-Agent")))
			
			return
		}
	}
	
	// Check if IP has accessed honeypots recently
	clientIP := fr.getClientIP(r)
	if lastAccess, exists := fr.honeypots[clientIP]; exists {
		if time.Since(lastAccess) < time.Hour*24 {
			result.Score -= 50
			result.ThreatLevel = "HIGH"
			result.Warnings = append(result.Warnings, "IP previously accessed honeypot")
		}
	}
}

// setSecurityHeaders sets appropriate security headers
func (fr *FortressRampart) setSecurityHeaders(result *RampartSecurityResult) {
	if fr.config.EnforceHSTS {
		result.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
	}
	
	if fr.config.EnforceCSP {
		result.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
	}
	
	if fr.config.EnforceXFrameOptions {
		result.Headers["X-Frame-Options"] = "DENY"
	}
	
	if fr.config.EnforceXContentType {
		result.Headers["X-Content-Type-Options"] = "nosniff"
	}
	
	// Always set security headers
	result.Headers["X-XSS-Protection"] = "1; mode=block"
	result.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
	result.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
}

// Helper methods

// getClientIP extracts the real client IP from the request
func (fr *FortressRampart) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (if from trusted proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Fall back to remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// containsSuspiciousContent checks for suspicious content in headers
func (fr *FortressRampart) containsSuspiciousContent(value string) bool {
	suspicious := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "eval(", "document.cookie",
		"alert(", "prompt(", "confirm(",
	}
	
	valueLower := strings.ToLower(value)
	for _, pattern := range suspicious {
		if strings.Contains(valueLower, pattern) {
			return true
		}
	}
	
	return false
}

// isSuspiciousUserAgent detects suspicious user agent patterns
func (fr *FortressRampart) isSuspiciousUserAgent(userAgent string) bool {
	// Check for very short user agents
	if len(userAgent) < 10 {
		return true
	}
	
	// Check for missing common browser identifiers
	commonBrowsers := []string{"Mozilla", "Chrome", "Safari", "Firefox", "Edge"}
	hasCommonBrowser := false
	for _, browser := range commonBrowsers {
		if strings.Contains(userAgent, browser) {
			hasCommonBrowser = true
			break
		}
	}
	
	// Check for suspicious patterns
	suspicious := []string{"python", "java", "curl", "wget", "scanner", "test"}
	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspicious {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	
	return !hasCommonBrowser
}

// hasSuspiciousHeaderOrder checks for suspicious header ordering
func (fr *FortressRampart) hasSuspiciousHeaderOrder(r *http.Request) bool {
	// Real browsers typically send headers in a specific order
	// This is a simplified check - a real implementation would be more sophisticated
	headers := make([]string, 0, len(r.Header))
	for name := range r.Header {
		headers = append(headers, name)
	}
	
	// Check if User-Agent comes before Accept (common in automated tools)
	userAgentIndex := -1
	acceptIndex := -1
	
	for i, header := range headers {
		if strings.EqualFold(header, "User-Agent") {
			userAgentIndex = i
		}
		if strings.EqualFold(header, "Accept") {
			acceptIndex = i
		}
	}
	
	// Suspicious if User-Agent comes before Accept
	return userAgentIndex != -1 && acceptIndex != -1 && userAgentIndex < acceptIndex
}

// hasSuspiciousRequestPattern detects suspicious request patterns
func (fr *FortressRampart) hasSuspiciousRequestPattern(r *http.Request) bool {
	// Check for suspicious URL patterns
	suspiciousPatterns := []string{
		"../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
		"<script", "javascript:", "vbscript:",
		"union+select", "drop+table", "insert+into",
	}
	
	url := strings.ToLower(r.URL.String())
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}
	
	// Check for suspicious parameter names
	suspiciousParams := []string{"cmd", "exec", "system", "eval", "file", "dir", "path"}
	for param := range r.URL.Query() {
		paramLower := strings.ToLower(param)
		for _, suspicious := range suspiciousParams {
			if paramLower == suspicious {
				return true
			}
		}
	}
	
	return false
}

// isTimeInRange checks if current time falls within the specified range
func (fr *FortressRampart) isTimeInRange(now time.Time, timeRange TimeRange) bool {
	// Load timezone
	loc, err := time.LoadLocation(timeRange.Timezone)
	if err != nil {
		loc = time.UTC // Default to UTC if timezone is invalid
	}
	
	nowInTZ := now.In(loc)
	weekday := int(nowInTZ.Weekday())
	
	// Check if current day is in allowed days
	dayAllowed := false
	for _, day := range timeRange.Days {
		if day == weekday {
			dayAllowed = true
			break
		}
	}
	
	if !dayAllowed {
		return false
	}
	
	// Parse start and end times
	startTime, err := time.Parse("15:04", timeRange.Start)
	if err != nil {
		return false
	}
	
	endTime, err := time.Parse("15:04", timeRange.End)
	if err != nil {
		return false
	}
	
	// Get current time in HH:MM format
	currentTime := time.Date(0, 1, 1, nowInTZ.Hour(), nowInTZ.Minute(), 0, 0, time.UTC)
	
	// Handle overnight ranges (e.g., 22:00-06:00)
	if endTime.Before(startTime) {
		return currentTime.After(startTime) || currentTime.Before(endTime)
	}
	
	return currentTime.After(startTime) && currentTime.Before(endTime)
}

// calculateThreatLevel calculates final threat level based on score and violations
func (fr *FortressRampart) calculateThreatLevel(result *RampartSecurityResult) {
	if result.Score <= 0 {
		result.ThreatLevel = "CRITICAL"
	} else if result.Score <= 30 {
		result.ThreatLevel = "HIGH"
	} else if result.Score <= 60 {
		result.ThreatLevel = "MEDIUM"
	} else if result.Score <= 80 {
		result.ThreatLevel = "LOW"
	} else {
		result.ThreatLevel = "SAFE"
	}
	
	// Override if critical violations are present
	for _, violation := range result.Violations {
		if strings.Contains(violation, "HONEYPOT") || strings.Contains(violation, "CRITICAL") {
			result.ThreatLevel = "CRITICAL"
			break
		}
	}
}

// GetConfig returns the current rampart configuration
func (fr *FortressRampart) GetConfig() *RampartSecurityConfig {
	return fr.config
}

// UpdateConfig updates the rampart configuration
func (fr *FortressRampart) UpdateConfig(config *RampartSecurityConfig) {
	fr.config = config
	fr.logger.Info("Fortress rampart configuration updated")
}