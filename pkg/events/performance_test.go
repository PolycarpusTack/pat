package events_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventsv1 "github.com/pat/api/events/v1"
	"github.com/pat/pkg/events"
)

// TestProducerPerformance tests if we can achieve 10,000 events/second
func TestProducerPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	logger, _ := zap.NewDevelopment()
	
	config := events.ProducerConfig{
		Brokers:          []string{"localhost:9092"},
		Topic:            "pat-events-perf-test",
		FlushTimeout:     5 * time.Second,
		BatchSize:        1000,
		CompressionType:  "lz4",
		IdempotenceEnable: true,
	}

	producer, err := events.NewProducer(config, logger)
	require.NoError(t, err)
	defer producer.Close()

	// Target: 10,000 events/second
	targetEventsPerSecond := 10000
	duration := 10 * time.Second
	totalEvents := targetEventsPerSecond * int(duration.Seconds())

	// Create a pool of pre-generated events to reduce allocation overhead
	eventPool := make([]*eventsv1.EmailReceived, 1000)
	for i := range eventPool {
		eventPool[i] = generateTestEmailReceived()
	}

	// Metrics
	var sentCount int64
	var errorCount int64

	// Start time
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	// Launch multiple goroutines to send events
	numWorkers := 10
	eventsPerWorker := totalEvents / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for i := 0; i < eventsPerWorker; i++ {
				event := eventPool[i%len(eventPool)]
				// Clone event with new ID
				eventCopy := *event
				eventCopy.EmailId = uuid.New().String()
				eventCopy.Metadata.EventId = uuid.New().String()

				if err := producer.SendEmailReceived(ctx, &eventCopy); err != nil {
					atomic.AddInt64(&errorCount, 1)
					if atomic.LoadInt64(&errorCount) < 10 {
						t.Logf("Worker %d: Failed to send event: %v", workerID, err)
					}
				} else {
					atomic.AddInt64(&sentCount, 1)
				}

				// Check if we should stop
				if time.Since(start) > duration {
					return
				}
			}
		}(w)
	}

	// Monitor progress
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				sent := atomic.LoadInt64(&sentCount)
				elapsed := time.Since(start).Seconds()
				rate := float64(sent) / elapsed
				t.Logf("Progress: %d events sent, %.2f events/second", sent, rate)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers
	wg.Wait()

	// Flush remaining messages
	require.NoError(t, producer.Flush(ctx))

	// Calculate results
	elapsed := time.Since(start)
	finalSent := atomic.LoadInt64(&sentCount)
	finalErrors := atomic.LoadInt64(&errorCount)
	actualRate := float64(finalSent) / elapsed.Seconds()

	// Get producer metrics
	metrics := producer.GetMetrics()

	// Report results
	t.Logf("\n=== Performance Test Results ===")
	t.Logf("Duration: %v", elapsed)
	t.Logf("Total events attempted: %d", totalEvents)
	t.Logf("Total events sent: %d", finalSent)
	t.Logf("Total errors: %d", finalErrors)
	t.Logf("Success rate: %.2f%%", float64(finalSent)/float64(totalEvents)*100)
	t.Logf("Actual rate: %.2f events/second", actualRate)
	t.Logf("Target rate: %d events/second", targetEventsPerSecond)
	t.Logf("Producer metrics: %+v", metrics)

	// Assertions
	assert.Greater(t, actualRate, float64(targetEventsPerSecond)*0.95, 
		"Should achieve at least 95% of target rate")
	assert.Less(t, float64(finalErrors), float64(totalEvents)*0.01, 
		"Error rate should be less than 1%")
}

// TestConsumerPerformance tests if consumer can keep up with 10,000 events/second
func TestConsumerPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	logger, _ := zap.NewDevelopment()

	// Test handler that just counts messages
	handler := &performanceTestHandler{
		processDelay: 0, // No artificial delay
	}

	config := events.ConsumerConfig{
		Brokers:          []string{"localhost:9092"},
		Topics:           []string{"pat-events-perf-test"},
		GroupID:          "pat-perf-test-consumer",
		AutoOffsetReset:  "latest",
		EnableAutoCommit: false,
	}

	consumer, err := events.NewConsumer(config, handler, logger)
	require.NoError(t, err)
	defer consumer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start consumer
	require.NoError(t, consumer.Start(ctx))

	// Monitor progress
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				processed := atomic.LoadInt64(&handler.processed)
				t.Logf("Consumer progress: %d events processed", processed)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for test duration
	time.Sleep(20 * time.Second)

	// Stop consumer
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	require.NoError(t, consumer.Stop(stopCtx))

	// Get consumer metrics
	metrics := consumer.GetMetrics()

	// Report results
	t.Logf("\n=== Consumer Performance Results ===")
	t.Logf("Total processed: %d", handler.processed)
	t.Logf("Total errors: %d", handler.errors)
	t.Logf("Average processing time: %v", time.Duration(handler.totalTime/handler.processed))
	t.Logf("Consumer metrics: %+v", metrics)

	// Calculate processing rate
	processingRate := float64(handler.processed) / 20.0
	t.Logf("Processing rate: %.2f events/second", processingRate)

	// Assertions
	assert.Greater(t, processingRate, 9500.0, 
		"Consumer should process at least 9,500 events/second")
	assert.Less(t, float64(handler.errors), float64(handler.processed)*0.01,
		"Error rate should be less than 1%")
}

// performanceTestHandler is a test implementation of EventHandler
type performanceTestHandler struct {
	processed    int64
	errors       int64
	totalTime    int64 // nanoseconds
	processDelay time.Duration
}

func (h *performanceTestHandler) HandleEmailReceived(ctx context.Context, event *eventsv1.EmailReceived) error {
	start := time.Now()
	defer func() {
		atomic.AddInt64(&h.totalTime, time.Since(start).Nanoseconds())
		atomic.AddInt64(&h.processed, 1)
	}()

	// Simulate processing
	if h.processDelay > 0 {
		time.Sleep(h.processDelay)
	}

	// Randomly fail 0.1% of messages to test error handling
	if time.Now().UnixNano()%1000 == 0 {
		atomic.AddInt64(&h.errors, 1)
		return fmt.Errorf("simulated processing error")
	}

	return nil
}

func (h *performanceTestHandler) HandleEmailProcessed(ctx context.Context, event *eventsv1.EmailProcessed) error {
	atomic.AddInt64(&h.processed, 1)
	return nil
}

func (h *performanceTestHandler) HandleEmailValidated(ctx context.Context, event *eventsv1.EmailValidated) error {
	atomic.AddInt64(&h.processed, 1)
	return nil
}

func (h *performanceTestHandler) HandleWorkflowTriggered(ctx context.Context, event *eventsv1.WorkflowTriggered) error {
	atomic.AddInt64(&h.processed, 1)
	return nil
}

func (h *performanceTestHandler) HandlePluginExecutionRequired(ctx context.Context, event *eventsv1.PluginExecutionRequired) error {
	atomic.AddInt64(&h.processed, 1)
	return nil
}

// generateTestEmailReceived creates a test EmailReceived event
func generateTestEmailReceived() *eventsv1.EmailReceived {
	return &eventsv1.EmailReceived{
		Metadata: &eventsv1.EventMetadata{
			EventId:       uuid.New().String(),
			CorrelationId: uuid.New().String(),
			Source:        "test",
			Timestamp:     timestamppb.Now(),
			Attributes:    map[string]string{"test": "true"},
		},
		EmailId:   uuid.New().String(),
		MessageId: fmt.Sprintf("<%s@test.example.com>", uuid.New().String()),
		From: &eventsv1.EmailAddress{
			Address: "sender@example.com",
			Name:    "Test Sender",
		},
		To: []*eventsv1.EmailAddress{
			{Address: "recipient@example.com", Name: "Test Recipient"},
		},
		Subject:    "Performance Test Email",
		TextBody:   "This is a performance test email body.",
		HtmlBody:   "<p>This is a performance test email body.</p>",
		Protocol:   "smtp",
		SourceIp:   "127.0.0.1",
		SourcePort: 25,
		ReceivedAt: timestamppb.Now(),
		SizeBytes:  1024,
	}
}