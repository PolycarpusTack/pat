package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/alexandria/pat-plugin/pkg/email"
)

// EmailAnalyzer provides AI-powered email analysis capabilities
type EmailAnalyzer struct {
	sentimentAnalyzer *SentimentAnalyzer
	spamDetector     *SpamDetector
	intentClassifier *IntentClassifier
	anomalyDetector  *AnomalyDetector
	contentExtractor *ContentExtractor
}

// AnalysisResult contains comprehensive email analysis results
type AnalysisResult struct {
	EmailID          string                 `json:"email_id"`
	Timestamp        time.Time              `json:"timestamp"`
	Sentiment        SentimentResult        `json:"sentiment"`
	SpamScore        SpamResult             `json:"spam_score"`
	Intent           IntentResult           `json:"intent"`
	Anomalies        []AnomalyResult        `json:"anomalies"`
	ContentAnalysis  ContentAnalysisResult  `json:"content_analysis"`
	SecurityRisks    []SecurityRisk         `json:"security_risks"`
	Recommendations  []string               `json:"recommendations"`
	ProcessingTime   time.Duration          `json:"processing_time"`
}

// SentimentResult represents sentiment analysis output
type SentimentResult struct {
	Score      float64            `json:"score"`      // -1 to 1 (negative to positive)
	Confidence float64            `json:"confidence"` // 0 to 1
	Label      string             `json:"label"`      // positive, negative, neutral
	Emotions   map[string]float64 `json:"emotions"`   // joy, anger, fear, sadness, etc.
}

// SpamResult represents spam detection output
type SpamResult struct {
	Score         float64            `json:"score"`          // 0 to 1 (not spam to definitely spam)
	Probability   float64            `json:"probability"`    // 0 to 1
	Classification string            `json:"classification"` // spam, ham, suspicious
	Features      map[string]float64 `json:"features"`       // feature scores
	Rules         []string           `json:"rules"`          // triggered rules
}

// IntentResult represents intent classification output
type IntentResult struct {
	Primary     string             `json:"primary"`     // primary intent
	Secondary   []string           `json:"secondary"`   // secondary intents
	Confidence  float64            `json:"confidence"`  // 0 to 1
	Categories  map[string]float64 `json:"categories"`  // category scores
}

// AnomalyResult represents detected anomalies
type AnomalyResult struct {
	Type        string  `json:"type"`        // type of anomaly
	Severity    string  `json:"severity"`    // low, medium, high, critical
	Score       float64 `json:"score"`       // anomaly score
	Description string  `json:"description"` // human-readable description
	Context     string  `json:"context"`     // relevant context
}

// ContentAnalysisResult represents content analysis output
type ContentAnalysisResult struct {
	Language       string              `json:"language"`
	Topics         []Topic             `json:"topics"`
	KeyPhrases     []KeyPhrase         `json:"key_phrases"`
	Entities       []Entity            `json:"entities"`
	ReadabilityScore float64           `json:"readability_score"`
	WordCount      int                 `json:"word_count"`
	UniqueWords    int                 `json:"unique_words"`
	Complexity     string              `json:"complexity"` // simple, moderate, complex
}

// Topic represents identified topics
type Topic struct {
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Keywords   []string `json:"keywords"`
}

// KeyPhrase represents important phrases
type KeyPhrase struct {
	Text       string  `json:"text"`
	Relevance  float64 `json:"relevance"`
	Frequency  int     `json:"frequency"`
}

// Entity represents named entities
type Entity struct {
	Text       string  `json:"text"`
	Type       string  `json:"type"`       // PERSON, ORGANIZATION, LOCATION, etc.
	Confidence float64 `json:"confidence"`
	StartPos   int     `json:"start_pos"`
	EndPos     int     `json:"end_pos"`
}

// SecurityRisk represents potential security risks
type SecurityRisk struct {
	Type        string  `json:"type"`        // phishing, malware, social_engineering
	Severity    string  `json:"severity"`    // low, medium, high, critical
	Confidence  float64 `json:"confidence"`  // 0 to 1
	Description string  `json:"description"`
	Evidence    []string `json:"evidence"`    // supporting evidence
	Mitigation  string  `json:"mitigation"`  // suggested mitigation
}

// NewEmailAnalyzer creates a new AI email analyzer
func NewEmailAnalyzer(config *AnalyzerConfig) *EmailAnalyzer {
	return &EmailAnalyzer{
		sentimentAnalyzer: NewSentimentAnalyzer(config.SentimentConfig),
		spamDetector:     NewSpamDetector(config.SpamConfig),
		intentClassifier: NewIntentClassifier(config.IntentConfig),
		anomalyDetector:  NewAnomalyDetector(config.AnomalyConfig),
		contentExtractor: NewContentExtractor(config.ContentConfig),
	}
}

// AnalyzeEmail performs comprehensive AI analysis on an email
func (ea *EmailAnalyzer) AnalyzeEmail(ctx context.Context, email *email.Email) (*AnalysisResult, error) {
	startTime := time.Now()
	
	result := &AnalysisResult{
		EmailID:   email.ID,
		Timestamp: time.Now(),
	}
	
	// Extract text content for analysis
	textContent := ea.extractTextContent(email)
	if textContent == "" {
		return nil, fmt.Errorf("no text content found for analysis")
	}
	
	// Parallel analysis execution
	errChan := make(chan error, 6)
	
	// Sentiment analysis
	go func() {
		sentiment, err := ea.sentimentAnalyzer.AnalyzeSentiment(ctx, textContent)
		if err != nil {
			errChan <- fmt.Errorf("sentiment analysis failed: %w", err)
			return
		}
		result.Sentiment = *sentiment
		errChan <- nil
	}()
	
	// Spam detection
	go func() {
		spam, err := ea.spamDetector.DetectSpam(ctx, email)
		if err != nil {
			errChan <- fmt.Errorf("spam detection failed: %w", err)
			return
		}
		result.SpamScore = *spam
		errChan <- nil
	}()
	
	// Intent classification
	go func() {
		intent, err := ea.intentClassifier.ClassifyIntent(ctx, textContent, email)
		if err != nil {
			errChan <- fmt.Errorf("intent classification failed: %w", err)
			return
		}
		result.Intent = *intent
		errChan <- nil
	}()
	
	// Anomaly detection
	go func() {
		anomalies, err := ea.anomalyDetector.DetectAnomalies(ctx, email)
		if err != nil {
			errChan <- fmt.Errorf("anomaly detection failed: %w", err)
			return
		}
		result.Anomalies = anomalies
		errChan <- nil
	}()
	
	// Content analysis
	go func() {
		content, err := ea.contentExtractor.AnalyzeContent(ctx, textContent)
		if err != nil {
			errChan <- fmt.Errorf("content analysis failed: %w", err)
			return
		}
		result.ContentAnalysis = *content
		errChan <- nil
	}()
	
	// Security risk analysis
	go func() {
		risks, err := ea.analyzeSecurityRisks(ctx, email, textContent)
		if err != nil {
			errChan <- fmt.Errorf("security analysis failed: %w", err)
			return
		}
		result.SecurityRisks = risks
		errChan <- nil
	}()
	
	// Wait for all analyses to complete
	for i := 0; i < 6; i++ {
		if err := <-errChan; err != nil {
			return nil, err
		}
	}
	
	// Generate recommendations based on analysis results
	result.Recommendations = ea.generateRecommendations(result)
	result.ProcessingTime = time.Since(startTime)
	
	return result, nil
}

// extractTextContent extracts plain text from email for analysis
func (ea *EmailAnalyzer) extractTextContent(email *email.Email) string {
	var content strings.Builder
	
	// Add subject
	if email.Subject != "" {
		content.WriteString(email.Subject)
		content.WriteString("\n\n")
	}
	
	// Prefer plain text, fall back to HTML
	if email.TextBody != "" {
		content.WriteString(email.TextBody)
	} else if email.HTMLBody != "" {
		// Strip HTML tags (simplified)
		htmlStripped := stripHTMLTags(email.HTMLBody)
		content.WriteString(htmlStripped)
	}
	
	return content.String()
}

// analyzeSecurityRisks analyzes potential security risks in the email
func (ea *EmailAnalyzer) analyzeSecurityRisks(ctx context.Context, email *email.Email, textContent string) ([]SecurityRisk, error) {
	var risks []SecurityRisk
	
	// Phishing detection
	phishingRisk := ea.detectPhishing(email, textContent)
	if phishingRisk != nil {
		risks = append(risks, *phishingRisk)
	}
	
	// Malware detection (attachments)
	malwareRisks := ea.detectMalware(email)
	risks = append(risks, malwareRisks...)
	
	// Social engineering detection
	socialEngRisk := ea.detectSocialEngineering(textContent)
	if socialEngRisk != nil {
		risks = append(risks, *socialEngRisk)
	}
	
	// Suspicious links detection
	linkRisks := ea.detectSuspiciousLinks(textContent)
	risks = append(risks, linkRisks...)
	
	return risks, nil
}

// detectPhishing detects potential phishing attempts
func (ea *EmailAnalyzer) detectPhishing(email *email.Email, textContent string) *SecurityRisk {
	var score float64
	var evidence []string
	
	// Check for urgent language
	urgentPatterns := []string{
		"urgent", "immediate", "expire", "suspend", "verify now",
		"act now", "limited time", "click here", "update payment",
	}
	
	for _, pattern := range urgentPatterns {
		if strings.Contains(strings.ToLower(textContent), pattern) {
			score += 0.2
			evidence = append(evidence, fmt.Sprintf("Urgent language: %s", pattern))
		}
	}
	
	// Check sender domain vs claimed domain
	if ea.checkDomainSpoofing(email) {
		score += 0.4
		evidence = append(evidence, "Potential domain spoofing detected")
	}
	
	// Check for suspicious links
	suspiciousLinks := ea.findSuspiciousLinks(textContent)
	if len(suspiciousLinks) > 0 {
		score += 0.3
		evidence = append(evidence, fmt.Sprintf("Suspicious links found: %v", suspiciousLinks))
	}
	
	if score > 0.3 {
		severity := "medium"
		if score > 0.7 {
			severity = "high"
		}
		
		return &SecurityRisk{
			Type:        "phishing",
			Severity:    severity,
			Confidence:  score,
			Description: "Potential phishing attempt detected based on content analysis",
			Evidence:    evidence,
			Mitigation:  "Verify sender identity through alternative channels before taking any action",
		}
	}
	
	return nil
}

// detectMalware detects potential malware in attachments
func (ea *EmailAnalyzer) detectMalware(email *email.Email) []SecurityRisk {
	var risks []SecurityRisk
	
	dangerousExtensions := []string{
		".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
		".jar", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm",
	}
	
	for _, attachment := range email.Attachments {
		filename := strings.ToLower(attachment.Filename)
		
		for _, ext := range dangerousExtensions {
			if strings.HasSuffix(filename, ext) {
				risks = append(risks, SecurityRisk{
					Type:        "malware",
					Severity:    "high",
					Confidence:  0.8,
					Description: fmt.Sprintf("Potentially dangerous attachment: %s", attachment.Filename),
					Evidence:    []string{fmt.Sprintf("File extension: %s", ext)},
					Mitigation:  "Scan attachment with antivirus before opening",
				})
			}
		}
	}
	
	return risks
}

// detectSocialEngineering detects social engineering attempts
func (ea *EmailAnalyzer) detectSocialEngineering(textContent string) *SecurityRisk {
	socialEngPatterns := []string{
		"help me", "need your assistance", "urgent help needed",
		"transfer money", "lottery winner", "inheritance",
		"prince", "princess", "government official",
		"confidential", "secret", "off the record",
	}
	
	var score float64
	var evidence []string
	
	text := strings.ToLower(textContent)
	for _, pattern := range socialEngPatterns {
		if strings.Contains(text, pattern) {
			score += 0.15
			evidence = append(evidence, fmt.Sprintf("Social engineering indicator: %s", pattern))
		}
	}
	
	if score > 0.3 {
		return &SecurityRisk{
			Type:        "social_engineering",
			Severity:    "medium",
			Confidence:  score,
			Description: "Potential social engineering attempt detected",
			Evidence:    evidence,
			Mitigation:  "Be cautious of requests for personal information or financial assistance",
		}
	}
	
	return nil
}

// detectSuspiciousLinks detects suspicious URLs in email content
func (ea *EmailAnalyzer) detectSuspiciousLinks(textContent string) []SecurityRisk {
	var risks []SecurityRisk
	
	// URL regex pattern
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	urls := urlPattern.FindAllString(textContent, -1)
	
	for _, url := range urls {
		if ea.isSuspiciousURL(url) {
			risks = append(risks, SecurityRisk{
				Type:        "suspicious_link",
				Severity:    "medium",
				Confidence:  0.7,
				Description: fmt.Sprintf("Suspicious URL detected: %s", url),
				Evidence:    []string{"URL analysis indicates potential threat"},
				Mitigation:  "Verify URL destination before clicking",
			})
		}
	}
	
	return risks
}

// Helper functions

func (ea *EmailAnalyzer) checkDomainSpoofing(email *email.Email) bool {
	// Simplified domain spoofing check
	senderDomain := extractDomain(email.From.Address)
	
	// Check against known domains that are commonly spoofed
	commonDomains := []string{"paypal.com", "amazon.com", "microsoft.com", "google.com"}
	
	for _, domain := range commonDomains {
		if strings.Contains(senderDomain, domain) && senderDomain != domain {
			return true
		}
	}
	
	return false
}

func (ea *EmailAnalyzer) findSuspiciousLinks(textContent string) []string {
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	urls := urlPattern.FindAllString(textContent, -1)
	
	var suspicious []string
	for _, url := range urls {
		if ea.isSuspiciousURL(url) {
			suspicious = append(suspicious, url)
		}
	}
	
	return suspicious
}

func (ea *EmailAnalyzer) isSuspiciousURL(url string) bool {
	// Check for URL shorteners
	shorteners := []string{"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}
	
	for _, shortener := range shorteners {
		if strings.Contains(url, shortener) {
			return true
		}
	}
	
	// Check for suspicious TLDs
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf"}
	
	for _, tld := range suspiciousTLDs {
		if strings.Contains(url, tld) {
			return true
		}
	}
	
	// Check for IP addresses instead of domains
	ipPattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	if ipPattern.MatchString(url) {
		return true
	}
	
	return false
}

func (ea *EmailAnalyzer) generateRecommendations(result *AnalysisResult) []string {
	var recommendations []string
	
	// Spam recommendations
	if result.SpamScore.Score > 0.7 {
		recommendations = append(recommendations, "Email classified as spam - consider blocking sender")
	} else if result.SpamScore.Score > 0.3 {
		recommendations = append(recommendations, "Email shows spam characteristics - verify sender authenticity")
	}
	
	// Security recommendations
	if len(result.SecurityRisks) > 0 {
		recommendations = append(recommendations, "Security risks detected - exercise caution with links and attachments")
	}
	
	// Sentiment recommendations
	if result.Sentiment.Score < -0.5 {
		recommendations = append(recommendations, "Negative sentiment detected - may require priority attention")
	}
	
	// Anomaly recommendations
	for _, anomaly := range result.Anomalies {
		if anomaly.Severity == "high" || anomaly.Severity == "critical" {
			recommendations = append(recommendations, fmt.Sprintf("High-severity anomaly detected: %s", anomaly.Description))
		}
	}
	
	return recommendations
}

// Utility functions

func stripHTMLTags(html string) string {
	// Simple HTML tag removal
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(html, "")
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

// BatchAnalyze analyzes multiple emails efficiently
func (ea *EmailAnalyzer) BatchAnalyze(ctx context.Context, emails []*email.Email, maxConcurrency int) ([]*AnalysisResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}
	
	semaphore := make(chan struct{}, maxConcurrency)
	results := make([]*AnalysisResult, len(emails))
	errChan := make(chan error, len(emails))
	
	for i, email := range emails {
		go func(idx int, e *email.Email) {
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			result, err := ea.AnalyzeEmail(ctx, e)
			if err != nil {
				errChan <- fmt.Errorf("failed to analyze email %s: %w", e.ID, err)
				return
			}
			
			results[idx] = result
			errChan <- nil
		}(i, email)
	}
	
	// Wait for all analyses to complete
	var errors []error
	for i := 0; i < len(emails); i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}
	
	if len(errors) > 0 {
		return results, fmt.Errorf("batch analysis completed with %d errors", len(errors))
	}
	
	return results, nil
}

// GetAnalysisStats returns statistics about analysis results
func (ea *EmailAnalyzer) GetAnalysisStats(results []*AnalysisResult) *AnalysisStats {
	stats := &AnalysisStats{
		TotalAnalyzed: len(results),
	}
	
	var totalProcessingTime time.Duration
	var spamCount, phishingCount, malwareCount int
	var totalSentiment float64
	
	for _, result := range results {
		totalProcessingTime += result.ProcessingTime
		totalSentiment += result.Sentiment.Score
		
		if result.SpamScore.Score > 0.5 {
			spamCount++
		}
		
		for _, risk := range result.SecurityRisks {
			switch risk.Type {
			case "phishing":
				phishingCount++
			case "malware":
				malwareCount++
			}
		}
	}
	
	if len(results) > 0 {
		stats.AverageProcessingTime = totalProcessingTime / time.Duration(len(results))
		stats.AverageSentiment = totalSentiment / float64(len(results))
	}
	
	stats.SpamCount = spamCount
	stats.PhishingCount = phishingCount
	stats.MalwareCount = malwareCount
	
	return stats
}

// AnalysisStats contains analysis statistics
type AnalysisStats struct {
	TotalAnalyzed          int           `json:"total_analyzed"`
	AverageProcessingTime  time.Duration `json:"average_processing_time"`
	AverageSentiment       float64       `json:"average_sentiment"`
	SpamCount              int           `json:"spam_count"`
	PhishingCount          int           `json:"phishing_count"`
	MalwareCount           int           `json:"malware_count"`
}