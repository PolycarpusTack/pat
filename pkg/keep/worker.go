package keep

import (
	"context"
	"fmt"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// EmailWorker handles asynchronous email processing
type EmailWorker struct {
	ID      int
	service *KeepService
	logger  *zap.Logger
	
	// Worker state
	active    bool
	processed int64
	errors    int64
	startTime time.Time
}

// Start starts the email worker to process jobs from the queue
func (w *EmailWorker) Start(ctx context.Context, jobQueue <-chan *EmailProcessingJob, stopChan <-chan struct{}) {
	w.logger.Info("Email worker starting", zap.Int("worker_id", w.ID))
	
	w.active = true
	w.startTime = time.Now()
	defer func() {
		w.active = false
		w.logger.Info("Email worker stopped", 
			zap.Int("worker_id", w.ID),
			zap.Int64("processed", w.processed),
			zap.Int64("errors", w.errors),
			zap.Duration("uptime", time.Since(w.startTime)))
	}()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Email worker stopping due to context cancellation", zap.Int("worker_id", w.ID))
			return
		case <-stopChan:
			w.logger.Info("Email worker stopping due to stop signal", zap.Int("worker_id", w.ID))
			return
		case job := <-jobQueue:
			if job == nil {
				continue
			}
			w.processJob(job)
		}
	}
}

// processJob processes a single email processing job
func (w *EmailWorker) processJob(job *EmailProcessingJob) {
	w.logger.Debug("Processing job", 
		zap.Int("worker_id", w.ID),
		zap.String("job_id", job.ID),
		zap.String("email_id", job.Email.ID))

	startTime := time.Now()
	result := &ProcessingResult{
		Success:  false,
		Duration: 0,
		Metadata: make(map[string]interface{}),
	}

	defer func() {
		result.Duration = time.Since(startTime)
		
		// Send result back if channel is available
		select {
		case job.ResultChan <- result:
		default:
			w.logger.Warn("Result channel blocked, discarding result", 
				zap.String("job_id", job.ID))
		}

		// Update worker statistics
		if result.Success {
			w.processed++
		} else {
			w.errors++
		}

		w.service.stats.updateQueueSize(len(w.service.incomingQueue))
	}()

	// Set processing timeout
	ctx, cancel := context.WithTimeout(job.Context, w.service.config.EmailProcessing.ProcessingTimeout)
	defer cancel()

	// Process based on action type
	var err error
	switch job.Action {
	case ActionProcess:
		err = w.processEmailAction(ctx, job.Email)
	case ActionStore:
		err = w.service.StoreEmail(ctx, job.Email)
	case ActionUpdate:
		// Updates would require additional parameters in the job
		w.logger.Warn("Update action not fully implemented", zap.String("job_id", job.ID))
	case ActionDelete:
		err = w.service.DeleteEmail(ctx, job.Email.ID)
	default:
		err = fmt.Errorf("unknown processing action: %s", job.Action)
	}

	if err != nil {
		w.logger.Error("Job processing failed",
			zap.Error(err),
			zap.Int("worker_id", w.ID),
			zap.String("job_id", job.ID),
			zap.String("email_id", job.Email.ID),
			zap.Int("retry", job.Retries))

		// Handle retry logic
		if job.Retries < w.service.config.EmailProcessing.RetryAttempts {
			w.retryJob(job, err)
			return
		}

		result.Error = err
		result.Metadata["final_error"] = err.Error()
		result.Metadata["retries"] = job.Retries
	} else {
		result.Success = true
		result.Email = job.Email
		result.Metadata["processed_by"] = w.ID
	}

	w.logger.Debug("Job completed",
		zap.Int("worker_id", w.ID),
		zap.String("job_id", job.ID),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration))
}

// processEmailAction performs the core email processing
func (w *EmailWorker) processEmailAction(ctx context.Context, email *interfaces.Email) error {
	// Step 1: Process through email processor
	if err := w.service.processor.ProcessEmail(ctx, email); err != nil {
		return fmt.Errorf("processor failed: %w", err)
	}

	// Step 2: Store the email
	if err := w.service.StoreEmail(ctx, email); err != nil {
		return fmt.Errorf("storage failed: %w", err)
	}

	// Step 3: Run analytics if enabled
	if w.service.config.Analytics.Enabled && w.service.analyzer != nil {
		if err := w.service.analyzer.AnalyzeEmail(ctx, email); err != nil {
			w.logger.Warn("Analytics processing failed", 
				zap.Error(err), 
				zap.String("email_id", email.ID))
			// Don't fail the entire processing for analytics errors
		}
	}

	return nil
}

// retryJob schedules a job for retry
func (w *EmailWorker) retryJob(job *EmailProcessingJob, lastError error) {
	job.Retries++
	
	// Calculate retry delay with exponential backoff
	retryDelay := w.service.config.EmailProcessing.RetryDelay * time.Duration(job.Retries)
	
	w.logger.Info("Scheduling job retry",
		zap.String("job_id", job.ID),
		zap.Int("retry", job.Retries),
		zap.Duration("delay", retryDelay),
		zap.Error(lastError))

	// Schedule retry after delay
	go func() {
		time.Sleep(retryDelay)
		
		select {
		case w.service.incomingQueue <- job:
			w.logger.Debug("Job requeued for retry", zap.String("job_id", job.ID))
		default:
			w.logger.Error("Failed to requeue job - queue full", zap.String("job_id", job.ID))
			
			// Send final failure result
			result := &ProcessingResult{
				Success:  false,
				Error:    fmt.Errorf("failed to requeue job after %d retries: %w", job.Retries, lastError),
				Duration: 0,
				Metadata: map[string]interface{}{
					"retry_failed": true,
					"retries":      job.Retries,
				},
			}
			
			select {
			case job.ResultChan <- result:
			default:
			}
		}
	}()
}

// GetStats returns worker statistics
func (w *EmailWorker) GetStats() WorkerStats {
	return WorkerStats{
		ID:        w.ID,
		Active:    w.active,
		Processed: w.processed,
		Errors:    w.errors,
		Uptime:    time.Since(w.startTime),
		StartTime: w.startTime,
	}
}

// WorkerStats contains worker performance statistics
type WorkerStats struct {
	ID        int           `json:"id"`
	Active    bool          `json:"active"`
	Processed int64         `json:"processed"`
	Errors    int64         `json:"errors"`
	Uptime    time.Duration `json:"uptime"`
	StartTime time.Time     `json:"startTime"`
}

// EmailProcessor handles the core email processing logic
type EmailProcessor struct {
	config     *Config
	watchtower interfaces.Watchtower
	logger     *zap.Logger
}

// NewEmailProcessor creates a new email processor
func NewEmailProcessor(config *Config, watchtower interfaces.Watchtower, logger *zap.Logger) (*EmailProcessor, error) {
	return &EmailProcessor{
		config:     config,
		watchtower: watchtower,
		logger:     logger.Named("processor"),
	}, nil
}

// ProcessEmail processes an email through the fortress pipeline
func (p *EmailProcessor) ProcessEmail(ctx context.Context, email *interfaces.Email) error {
	p.logger.Debug("Processing email in processor", zap.String("email_id", email.ID))

	// Step 1: Normalize email headers
	if err := p.normalizeHeaders(email); err != nil {
		return fmt.Errorf("header normalization failed: %w", err)
	}

	// Step 2: Extract and process attachments
	if len(email.Attachments) > 0 {
		if err := p.processAttachments(ctx, email); err != nil {
			return fmt.Errorf("attachment processing failed: %w", err)
		}
	}

	// Step 3: Generate metadata
	p.generateMetadata(email)

	// Step 4: Update processing metrics
	p.updateMetrics(email)

	p.logger.Debug("Email processed successfully in processor", zap.String("email_id", email.ID))
	return nil
}

// normalizeHeaders normalizes email headers for consistent processing
func (p *EmailProcessor) normalizeHeaders(email *interfaces.Email) error {
	if email.Headers == nil {
		email.Headers = make(map[string]string)
	}

	// Normalize common headers
	for key, value := range email.Headers {
		switch strings.ToLower(key) {
		case "date":
			// Parse and normalize date format
			if parsedTime, err := time.Parse(time.RFC1123Z, value); err == nil {
				email.Headers["Date"] = parsedTime.Format(time.RFC1123Z)
			}
		case "message-id":
			email.MessageID = value
		case "from":
			email.From = value
		case "subject":
			email.Subject = value
		}
	}

	return nil
}

// processAttachments processes email attachments
func (p *EmailProcessor) processAttachments(ctx context.Context, email *interfaces.Email) error {
	for i := range email.Attachments {
		attachment := &email.Attachments[i]

		// Generate checksum for attachment
		if attachment.Checksum == "" {
			attachment.Checksum = p.generateChecksum(attachment.Content)
		}

		// Check attachment size limits
		if p.config.Storage.MaxEmailSize > 0 && attachment.Size > p.config.Storage.MaxEmailSize {
			return fmt.Errorf("attachment %s exceeds size limit", attachment.Name)
		}

		p.logger.Debug("Processed attachment",
			zap.String("name", attachment.Name),
			zap.String("type", attachment.Type),
			zap.Int64("size", attachment.Size),
			zap.String("checksum", attachment.Checksum))
	}

	return nil
}

// generateMetadata generates processing metadata for the email
func (p *EmailProcessor) generateMetadata(email *interfaces.Email) {
	if email.Metadata == nil {
		email.Metadata = make(map[string]interface{})
	}

	// Add processing metadata
	email.Metadata["processed_at"] = time.Now()
	email.Metadata["processor_version"] = "1.0.0"
	email.Metadata["attachment_count"] = len(email.Attachments)
	
	// Calculate email statistics
	email.Metadata["has_html"] = email.HTMLBody != ""
	email.Metadata["has_attachments"] = len(email.Attachments) > 0
	email.Metadata["recipient_count"] = len(email.To) + len(email.CC) + len(email.BCC)

	// Extract domain information
	if email.From != "" {
		if domain := extractDomain(email.From); domain != "unknown" {
			email.Metadata["from_domain"] = domain
		}
	}
}

// updateMetrics updates processing metrics
func (p *EmailProcessor) updateMetrics(email *interfaces.Email) {
	labels := map[string]string{
		"has_html":        fmt.Sprintf("%t", email.HTMLBody != ""),
		"has_attachments": fmt.Sprintf("%t", len(email.Attachments) > 0),
		"from_domain":     extractDomain(email.From),
	}

	p.watchtower.IncrementCounter("keep.processor.emails.processed", labels)
	p.watchtower.RecordHistogram("keep.processor.email.size", float64(email.Size), labels)
	
	if len(email.Attachments) > 0 {
		p.watchtower.RecordHistogram("keep.processor.attachments.count", float64(len(email.Attachments)), labels)
	}
}

// generateChecksum generates a checksum for attachment content
func (p *EmailProcessor) generateChecksum(content []byte) string {
	// Simple checksum implementation - use proper hashing in production
	sum := 0
	for _, b := range content {
		sum += int(b)
	}
	return fmt.Sprintf("%x", sum)
}

// Helper function to import strings package functionality
func strings_ToLower(s string) string {
	// This is a placeholder - import strings package in real implementation
	return s
}

func strings_Split(s, sep string) []string {
	// This is a placeholder - import strings package in real implementation
	return []string{s}
}