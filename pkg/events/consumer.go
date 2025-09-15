package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/pat/api/events/v1"
)

// ConsumerConfig holds configuration for the event consumer
type ConsumerConfig struct {
	Brokers          []string
	Topics           []string
	GroupID          string
	AutoOffsetReset  string
	SessionTimeout   time.Duration
	MaxPollInterval  time.Duration
	EnableAutoCommit bool
	SecurityProtocol string
	SaslMechanism    string
	SaslUsername     string
	SaslPassword     string
	TLSEnabled       bool
}

// EventHandler defines the interface for handling events
type EventHandler interface {
	HandleEmailReceived(ctx context.Context, event *eventsv1.EmailReceived) error
	HandleEmailProcessed(ctx context.Context, event *eventsv1.EmailProcessed) error
	HandleEmailValidated(ctx context.Context, event *eventsv1.EmailValidated) error
	HandleWorkflowTriggered(ctx context.Context, event *eventsv1.WorkflowTriggered) error
	HandlePluginExecutionRequired(ctx context.Context, event *eventsv1.PluginExecutionRequired) error
}

// Consumer wraps Kafka consumer with Pat-specific functionality
type Consumer struct {
	consumer    *kafka.Consumer
	config      ConsumerConfig
	handler     EventHandler
	logger      *zap.Logger
	tracer      trace.Tracer
	wg          sync.WaitGroup
	mu          sync.RWMutex
	closed      bool
	stopCh      chan struct{}
	metrics     *ConsumerMetrics
	retryPolicy *RetryPolicy
}

// ConsumerMetrics tracks consumer metrics
type ConsumerMetrics struct {
	MessagesReceived uint64
	MessagesProcessed uint64
	MessagesFailed   uint64
	ProcessingTime   time.Duration
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxRetries     int
	InitialDelay   time.Duration
	MaxDelay       time.Duration
	Multiplier     float64
	DLQTopic       string
}

// DefaultRetryPolicy returns a default retry policy
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		DLQTopic:     "pat-events-dlq",
	}
}

// NewConsumer creates a new event consumer
func NewConsumer(config ConsumerConfig, handler EventHandler, logger *zap.Logger) (*Consumer, error) {
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 10 * time.Second
	}
	if config.MaxPollInterval == 0 {
		config.MaxPollInterval = 5 * time.Minute
	}
	if config.AutoOffsetReset == "" {
		config.AutoOffsetReset = "latest"
	}

	kafkaConfig := kafka.ConfigMap{
		"bootstrap.servers":       config.Brokers,
		"group.id":                config.GroupID,
		"auto.offset.reset":       config.AutoOffsetReset,
		"enable.auto.commit":      config.EnableAutoCommit,
		"session.timeout.ms":      int(config.SessionTimeout.Milliseconds()),
		"max.poll.interval.ms":    int(config.MaxPollInterval.Milliseconds()),
		"enable.partition.eof":    false,
		"go.events.channel.enable": true,
		"go.events.channel.size":   1000,
	}

	// Configure security
	if config.SecurityProtocol != "" {
		kafkaConfig["security.protocol"] = config.SecurityProtocol
	}
	if config.SaslMechanism != "" {
		kafkaConfig["sasl.mechanism"] = config.SaslMechanism
		kafkaConfig["sasl.username"] = config.SaslUsername
		kafkaConfig["sasl.password"] = config.SaslPassword
	}

	consumer, err := kafka.NewConsumer(&kafkaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer: %w", err)
	}

	// Subscribe to topics
	if err := consumer.SubscribeTopics(config.Topics, nil); err != nil {
		consumer.Close()
		return nil, fmt.Errorf("failed to subscribe to topics: %w", err)
	}

	c := &Consumer{
		consumer:    consumer,
		config:      config,
		handler:     handler,
		logger:      logger,
		tracer:      otel.Tracer("pat.events.consumer"),
		stopCh:      make(chan struct{}),
		metrics:     &ConsumerMetrics{},
		retryPolicy: DefaultRetryPolicy(),
	}

	return c, nil
}

// Start begins consuming messages
func (c *Consumer) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("consumer is closed")
	}
	c.mu.Unlock()

	c.wg.Add(1)
	go c.consume(ctx)

	return nil
}

// consume is the main consumption loop
func (c *Consumer) consume(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
			ev := c.consumer.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				c.handleMessage(ctx, e)
			case kafka.Error:
				c.logger.Error("Kafka error", zap.Error(e))
			case kafka.AssignedPartitions:
				c.logger.Info("Partitions assigned",
					zap.Any("partitions", e.Partitions))
				c.consumer.Assign(e.Partitions)
			case kafka.RevokedPartitions:
				c.logger.Info("Partitions revoked",
					zap.Any("partitions", e.Partitions))
				c.consumer.Unassign()
			}
		}
	}
}

// handleMessage processes a single message
func (c *Consumer) handleMessage(ctx context.Context, msg *kafka.Message) {
	c.metrics.MessagesReceived++

	ctx, span := c.tracer.Start(ctx, "consumer.handleMessage",
		trace.WithAttributes(
			attribute.String("topic", *msg.TopicPartition.Topic),
			attribute.Int64("partition", int64(msg.TopicPartition.Partition)),
			attribute.Int64("offset", int64(msg.TopicPartition.Offset)),
		),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		c.metrics.ProcessingTime += time.Since(start)
	}()

	// Extract event type from headers
	eventType := c.extractEventType(msg.Headers)
	if eventType == "" {
		c.logger.Error("Message missing event-type header",
			zap.String("topic", *msg.TopicPartition.Topic),
			zap.Int64("offset", int64(msg.TopicPartition.Offset)),
		)
		c.commitMessage(msg)
		return
	}

	// Process with retry
	err := c.processMessageWithRetry(ctx, eventType, msg.Value)
	if err != nil {
		c.metrics.MessagesFailed++
		span.RecordError(err)
		c.logger.Error("Failed to process message after retries",
			zap.Error(err),
			zap.String("eventType", eventType),
		)
		
		// Send to DLQ
		if err := c.sendToDLQ(ctx, msg, err); err != nil {
			c.logger.Error("Failed to send message to DLQ", zap.Error(err))
		}
	} else {
		c.metrics.MessagesProcessed++
	}

	// Commit offset
	c.commitMessage(msg)
}

// processMessageWithRetry processes a message with retry logic
func (c *Consumer) processMessageWithRetry(ctx context.Context, eventType string, data []byte) error {
	var lastErr error
	delay := c.retryPolicy.InitialDelay

	for attempt := 0; attempt <= c.retryPolicy.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			
			// Calculate next delay
			delay = time.Duration(float64(delay) * c.retryPolicy.Multiplier)
			if delay > c.retryPolicy.MaxDelay {
				delay = c.retryPolicy.MaxDelay
			}
		}

		err := c.processMessage(ctx, eventType, data)
		if err == nil {
			return nil
		}

		lastErr = err
		c.logger.Warn("Message processing failed, retrying",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Duration("nextDelay", delay),
		)
	}

	return fmt.Errorf("failed after %d attempts: %w", c.retryPolicy.MaxRetries+1, lastErr)
}

// processMessage processes a single message based on its type
func (c *Consumer) processMessage(ctx context.Context, eventType string, data []byte) error {
	switch eventType {
	case "EmailReceived":
		var event eventsv1.EmailReceived
		if err := proto.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("failed to unmarshal EmailReceived: %w", err)
		}
		return c.handler.HandleEmailReceived(ctx, &event)

	case "EmailProcessed":
		var event eventsv1.EmailProcessed
		if err := proto.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("failed to unmarshal EmailProcessed: %w", err)
		}
		return c.handler.HandleEmailProcessed(ctx, &event)

	case "EmailValidated":
		var event eventsv1.EmailValidated
		if err := proto.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("failed to unmarshal EmailValidated: %w", err)
		}
		return c.handler.HandleEmailValidated(ctx, &event)

	case "WorkflowTriggered":
		var event eventsv1.WorkflowTriggered
		if err := proto.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("failed to unmarshal WorkflowTriggered: %w", err)
		}
		return c.handler.HandleWorkflowTriggered(ctx, &event)

	case "PluginExecutionRequired":
		var event eventsv1.PluginExecutionRequired
		if err := proto.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("failed to unmarshal PluginExecutionRequired: %w", err)
		}
		return c.handler.HandlePluginExecutionRequired(ctx, &event)

	default:
		return fmt.Errorf("unknown event type: %s", eventType)
	}
}

// extractEventType extracts the event type from message headers
func (c *Consumer) extractEventType(headers []kafka.Header) string {
	for _, header := range headers {
		if header.Key == "event-type" {
			return string(header.Value)
		}
	}
	return ""
}

// commitMessage commits the message offset
func (c *Consumer) commitMessage(msg *kafka.Message) {
	if !c.config.EnableAutoCommit {
		if _, err := c.consumer.CommitMessage(msg); err != nil {
			c.logger.Error("Failed to commit message",
				zap.Error(err),
				zap.String("topic", *msg.TopicPartition.Topic),
				zap.Int64("offset", int64(msg.TopicPartition.Offset)),
			)
		}
	}
}

// sendToDLQ sends failed messages to the dead letter queue
func (c *Consumer) sendToDLQ(ctx context.Context, msg *kafka.Message, err error) error {
	// This would typically use a producer instance
	// For now, we'll just log it
	c.logger.Error("Message sent to DLQ",
		zap.String("topic", *msg.TopicPartition.Topic),
		zap.Int64("offset", int64(msg.TopicPartition.Offset)),
		zap.Error(err),
	)
	return nil
}

// GetMetrics returns current consumer metrics
func (c *Consumer) GetMetrics() ConsumerMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c.metrics
}

// Stop stops the consumer gracefully
func (c *Consumer) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.stopCh)
	c.mu.Unlock()

	// Wait for consumption to stop
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes the consumer
func (c *Consumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.consumer != nil {
		return c.consumer.Close()
	}
	return nil
}