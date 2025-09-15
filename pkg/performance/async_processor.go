package performance

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
	"go.uber.org/zap"
)

// AsyncEmailProcessor provides high-performance asynchronous email processing
type AsyncEmailProcessor struct {
	logger       *zap.Logger
	store        legacy.FortressMessageStore
	workerPool   *WorkerPool
	messageQueue chan *ProcessingJob
	metrics      *ProcessingMetrics
	shutdown     chan struct{}
	wg           sync.WaitGroup
}

// ProcessingJob represents an email processing job
type ProcessingJob struct {
	Message   *legacy.Message
	Priority  JobPriority
	CreatedAt time.Time
	Retries   int
	MaxRetries int
	Callback  func(error)
}

// JobPriority defines processing priority levels
type JobPriority int

const (
	PriorityLow JobPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityUrgent
)

// ProcessingMetrics tracks performance metrics
type ProcessingMetrics struct {
	mutex               sync.RWMutex
	TotalProcessed      int64
	SuccessfulProcessed int64
	FailedProcessed     int64
	AverageProcessingTime time.Duration
	CurrentQueueSize    int64
	PeakQueueSize       int64
	WorkerUtilization   float64
	LastProcessedAt     time.Time
}

// WorkerPool manages a pool of processing workers
type WorkerPool struct {
	workers    []*Worker
	size       int
	jobQueue   chan *ProcessingJob
	workerWg   sync.WaitGroup
	shutdown   chan struct{}
	logger     *zap.Logger
}

// Worker represents a single processing worker
type Worker struct {
	id       int
	jobQueue chan *ProcessingJob
	quit     chan struct{}
	logger   *zap.Logger
	processor *AsyncEmailProcessor
}

// AsyncProcessorConfig defines configuration for the async processor
type AsyncProcessorConfig struct {
	WorkerCount       int
	QueueSize         int
	ProcessingTimeout time.Duration
	MaxRetries        int
	EnableMetrics     bool
	MetricsInterval   time.Duration
}

// NewAsyncEmailProcessor creates a new high-performance async email processor
func NewAsyncEmailProcessor(
	logger *zap.Logger,
	store legacy.FortressMessageStore,
	config *AsyncProcessorConfig,
) *AsyncEmailProcessor {
	if config == nil {
		config = DefaultAsyncProcessorConfig()
	}

	processor := &AsyncEmailProcessor{
		logger:       logger,
		store:        store,
		messageQueue: make(chan *ProcessingJob, config.QueueSize),
		metrics:      &ProcessingMetrics{},
		shutdown:     make(chan struct{}),
	}

	// Create worker pool
	processor.workerPool = NewWorkerPool(config.WorkerCount, processor.messageQueue, logger, processor)

	// Start metrics collection if enabled
	if config.EnableMetrics {
		go processor.metricsCollector(config.MetricsInterval)
	}

	logger.Info("AsyncEmailProcessor initialized",
		zap.Int("worker_count", config.WorkerCount),
		zap.Int("queue_size", config.QueueSize),
		zap.Duration("processing_timeout", config.ProcessingTimeout),
	)

	return processor
}

// DefaultAsyncProcessorConfig returns sensible default configuration
func DefaultAsyncProcessorConfig() *AsyncProcessorConfig {
	return &AsyncProcessorConfig{
		WorkerCount:       runtime.NumCPU() * 2, // 2 workers per CPU core
		QueueSize:         10000,                 // Large buffer for high throughput
		ProcessingTimeout: 30 * time.Second,
		MaxRetries:        3,
		EnableMetrics:     true,
		MetricsInterval:   30 * time.Second,
	}
}

// Start begins async processing
func (aep *AsyncEmailProcessor) Start() error {
	aep.logger.Info("Starting AsyncEmailProcessor")
	
	// Start worker pool
	aep.workerPool.Start()
	
	aep.logger.Info("AsyncEmailProcessor started successfully",
		zap.Int("active_workers", aep.workerPool.size),
	)
	
	return nil
}

// Stop gracefully shuts down the async processor
func (aep *AsyncEmailProcessor) Stop(ctx context.Context) error {
	aep.logger.Info("Stopping AsyncEmailProcessor")
	
	close(aep.shutdown)
	
	// Stop accepting new jobs
	close(aep.messageQueue)
	
	// Stop worker pool
	aep.workerPool.Stop()
	
	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		aep.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		aep.logger.Info("AsyncEmailProcessor stopped gracefully")
	case <-ctx.Done():
		aep.logger.Warn("AsyncEmailProcessor shutdown timeout exceeded")
		return ctx.Err()
	}
	
	return nil
}

// ProcessEmailAsync queues an email for asynchronous processing
func (aep *AsyncEmailProcessor) ProcessEmailAsync(
	message *legacy.Message,
	priority JobPriority,
	callback func(error),
) error {
	job := &ProcessingJob{
		Message:    message,
		Priority:   priority,
		CreatedAt:  time.Now(),
		MaxRetries: 3,
		Callback:   callback,
	}
	
	select {
	case aep.messageQueue <- job:
		aep.updateQueueMetrics(1)
		aep.logger.Debug("Email queued for processing",
			zap.String("message_id", string(message.ID)),
			zap.String("priority", priority.String()),
		)
		return nil
	case <-aep.shutdown:
		return ErrProcessorShutdown
	default:
		aep.logger.Warn("Processing queue full, dropping message",
			zap.String("message_id", string(message.ID)),
		)
		return ErrQueueFull
	}
}

// ProcessEmailSync provides synchronous processing for critical emails
func (aep *AsyncEmailProcessor) ProcessEmailSync(
	ctx context.Context,
	message *legacy.Message,
) error {
	startTime := time.Now()
	defer func() {
		aep.updateProcessingMetrics(time.Since(startTime), nil)
	}()
	
	// Process immediately on current goroutine
	_, err := aep.store.Store(message)
	if err != nil {
		aep.logger.Error("Synchronous email processing failed",
			zap.String("message_id", string(message.ID)),
			zap.Error(err),
		)
		aep.updateProcessingMetrics(time.Since(startTime), err)
		return err
	}
	
	aep.logger.Debug("Email processed synchronously",
		zap.String("message_id", string(message.ID)),
		zap.Duration("processing_time", time.Since(startTime)),
	)
	
	return nil
}

// GetMetrics returns current processing metrics
func (aep *AsyncEmailProcessor) GetMetrics() ProcessingMetrics {
	aep.metrics.mutex.RLock()
	defer aep.metrics.mutex.RUnlock()
	
	metrics := *aep.metrics
	metrics.CurrentQueueSize = int64(len(aep.messageQueue))
	
	return metrics
}

// updateQueueMetrics updates queue-related metrics
func (aep *AsyncEmailProcessor) updateQueueMetrics(delta int64) {
	aep.metrics.mutex.Lock()
	defer aep.metrics.mutex.Unlock()
	
	aep.metrics.CurrentQueueSize += delta
	if aep.metrics.CurrentQueueSize > aep.metrics.PeakQueueSize {
		aep.metrics.PeakQueueSize = aep.metrics.CurrentQueueSize
	}
}

// updateProcessingMetrics updates processing-related metrics
func (aep *AsyncEmailProcessor) updateProcessingMetrics(duration time.Duration, err error) {
	aep.metrics.mutex.Lock()
	defer aep.metrics.mutex.Unlock()
	
	aep.metrics.TotalProcessed++
	aep.metrics.LastProcessedAt = time.Now()
	
	if err == nil {
		aep.metrics.SuccessfulProcessed++
	} else {
		aep.metrics.FailedProcessed++
	}
	
	// Update average processing time (exponential moving average)
	alpha := 0.1 // Smoothing factor
	if aep.metrics.AverageProcessingTime == 0 {
		aep.metrics.AverageProcessingTime = duration
	} else {
		aep.metrics.AverageProcessingTime = time.Duration(
			float64(aep.metrics.AverageProcessingTime)*(1-alpha) + float64(duration)*alpha,
		)
	}
}

// metricsCollector runs periodic metrics collection
func (aep *AsyncEmailProcessor) metricsCollector(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			metrics := aep.GetMetrics()
			aep.logger.Info("Processing metrics",
				zap.Int64("total_processed", metrics.TotalProcessed),
				zap.Int64("successful", metrics.SuccessfulProcessed),
				zap.Int64("failed", metrics.FailedProcessed),
				zap.Duration("avg_processing_time", metrics.AverageProcessingTime),
				zap.Int64("current_queue_size", metrics.CurrentQueueSize),
				zap.Int64("peak_queue_size", metrics.PeakQueueSize),
				zap.Float64("worker_utilization", metrics.WorkerUtilization),
			)
		case <-aep.shutdown:
			return
		}
	}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(size int, jobQueue chan *ProcessingJob, logger *zap.Logger, processor *AsyncEmailProcessor) *WorkerPool {
	return &WorkerPool{
		size:     size,
		jobQueue: jobQueue,
		shutdown: make(chan struct{}),
		logger:   logger,
		workers:  make([]*Worker, 0, size),
	}
}

// Start starts all workers in the pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.size; i++ {
		worker := &Worker{
			id:        i + 1,
			jobQueue:  wp.jobQueue,
			quit:      make(chan struct{}),
			logger:    wp.logger,
			processor: nil, // Will be set by the processor
		}
		wp.workers = append(wp.workers, worker)
		
		wp.workerWg.Add(1)
		go worker.start(&wp.workerWg)
	}
	
	wp.logger.Info("Worker pool started", zap.Int("worker_count", wp.size))
}

// Stop stops all workers in the pool
func (wp *WorkerPool) Stop() {
	close(wp.shutdown)
	
	for _, worker := range wp.workers {
		close(worker.quit)
	}
	
	wp.workerWg.Wait()
	wp.logger.Info("Worker pool stopped")
}

// start begins worker processing loop
func (w *Worker) start(wg *sync.WaitGroup) {
	defer wg.Done()
	
	w.logger.Debug("Worker started", zap.Int("worker_id", w.id))
	
	for {
		select {
		case job := <-w.jobQueue:
			if job != nil {
				w.processJob(job)
			}
		case <-w.quit:
			w.logger.Debug("Worker stopping", zap.Int("worker_id", w.id))
			return
		}
	}
}

// processJob processes a single email job
func (w *Worker) processJob(job *ProcessingJob) {
	startTime := time.Now()
	
	w.logger.Debug("Processing email job",
		zap.Int("worker_id", w.id),
		zap.String("message_id", string(job.Message.ID)),
		zap.String("priority", job.Priority.String()),
		zap.Int("retry_count", job.Retries),
	)
	
	// Process the email
	_, err := w.processor.store.Store(job.Message)
	processingTime := time.Since(startTime)
	
	if err != nil {
		w.logger.Error("Job processing failed",
			zap.Int("worker_id", w.id),
			zap.String("message_id", string(job.Message.ID)),
			zap.Error(err),
			zap.Duration("processing_time", processingTime),
		)
		
		// Retry logic
		if job.Retries < job.MaxRetries {
			job.Retries++
			w.logger.Info("Retrying failed job",
				zap.String("message_id", string(job.Message.ID)),
				zap.Int("retry_count", job.Retries),
			)
			
			// Exponential backoff before retry
			go func() {
				backoff := time.Duration(job.Retries) * time.Second
				time.Sleep(backoff)
				w.jobQueue <- job
			}()
		} else {
			w.logger.Error("Job failed permanently after retries",
				zap.String("message_id", string(job.Message.ID)),
				zap.Int("max_retries", job.MaxRetries),
			)
		}
	} else {
		w.logger.Debug("Job processed successfully",
			zap.Int("worker_id", w.id),
			zap.String("message_id", string(job.Message.ID)),
			zap.Duration("processing_time", processingTime),
		)
	}
	
	// Update metrics
	if w.processor != nil {
		w.processor.updateProcessingMetrics(processingTime, err)
		w.processor.updateQueueMetrics(-1) // Decrement queue size
	}
	
	// Execute callback if provided
	if job.Callback != nil {
		job.Callback(err)
	}
}

// String returns string representation of job priority
func (jp JobPriority) String() string {
	switch jp {
	case PriorityLow:
		return "low"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityUrgent:
		return "urgent"
	default:
		return "unknown"
	}
}

// Common errors
var (
	ErrProcessorShutdown = &ProcessorError{Code: "PROCESSOR_SHUTDOWN", Message: "Async processor is shutting down"}
	ErrQueueFull        = &ProcessorError{Code: "QUEUE_FULL", Message: "Processing queue is full"}
)

// ProcessorError provides structured error handling
type ProcessorError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ProcessorError) Error() string {
	return e.Message
}