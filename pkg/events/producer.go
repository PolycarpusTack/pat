package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventsv1 "github.com/pat/api/events/v1"
)

const (
	defaultFlushTimeout = 5 * time.Second
	defaultBatchSize    = 100
)

// ProducerConfig holds configuration for the event producer
type ProducerConfig struct {
	Brokers          []string
	Topic            string
	FlushTimeout     time.Duration
	BatchSize        int
	CompressionType  string
	IdempotenceEnable bool
	SecurityProtocol string
	SaslMechanism    string
	SaslUsername     string
	SaslPassword     string
	TLSEnabled       bool
}

// Producer wraps Kafka producer with Pat-specific functionality
type Producer struct {
	producer    *kafka.Producer
	config      ProducerConfig
	logger      *zap.Logger
	tracer      trace.Tracer
	deliveryCh  chan kafka.Event
	errorCh     chan error
	wg          sync.WaitGroup
	mu          sync.RWMutex
	closed      bool
	metrics     *ProducerMetrics
}

// ProducerMetrics tracks producer metrics
type ProducerMetrics struct {
	MessagesSent      uint64
	MessagesDelivered uint64
	MessagesFailed    uint64
	BytesSent         uint64
}

// NewProducer creates a new event producer
func NewProducer(config ProducerConfig, logger *zap.Logger) (*Producer, error) {
	if config.FlushTimeout == 0 {
		config.FlushTimeout = defaultFlushTimeout
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultBatchSize
	}

	kafkaConfig := kafka.ConfigMap{
		"bootstrap.servers":  config.Brokers,
		"linger.ms":          50,
		"batch.size":         config.BatchSize,
		"compression.type":   config.CompressionType,
		"enable.idempotence": config.IdempotenceEnable,
		"acks":               "all",
		"retries":            10,
		"max.in.flight.requests.per.connection": 5,
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

	producer, err := kafka.NewProducer(&kafkaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create producer: %w", err)
	}

	p := &Producer{
		producer:    producer,
		config:      config,
		logger:      logger,
		tracer:      otel.Tracer("pat.events.producer"),
		deliveryCh:  make(chan kafka.Event, 1000),
		errorCh:     make(chan error, 100),
		metrics:     &ProducerMetrics{},
	}

	// Start delivery report handler
	p.wg.Add(1)
	go p.deliveryReportHandler()

	return p, nil
}

// SendEmailReceived sends an EmailReceived event
func (p *Producer) SendEmailReceived(ctx context.Context, event *eventsv1.EmailReceived) error {
	return p.sendEvent(ctx, "EmailReceived", event)
}

// SendEmailProcessed sends an EmailProcessed event
func (p *Producer) SendEmailProcessed(ctx context.Context, event *eventsv1.EmailProcessed) error {
	return p.sendEvent(ctx, "EmailProcessed", event)
}

// SendEmailValidated sends an EmailValidated event
func (p *Producer) SendEmailValidated(ctx context.Context, event *eventsv1.EmailValidated) error {
	return p.sendEvent(ctx, "EmailValidated", event)
}

// SendWorkflowTriggered sends a WorkflowTriggered event
func (p *Producer) SendWorkflowTriggered(ctx context.Context, event *eventsv1.WorkflowTriggered) error {
	return p.sendEvent(ctx, "WorkflowTriggered", event)
}

// SendPluginExecutionRequired sends a PluginExecutionRequired event
func (p *Producer) SendPluginExecutionRequired(ctx context.Context, event *eventsv1.PluginExecutionRequired) error {
	return p.sendEvent(ctx, "PluginExecutionRequired", event)
}

// sendEvent is the generic event sending method
func (p *Producer) sendEvent(ctx context.Context, eventType string, event proto.Message) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	p.mu.RUnlock()

	ctx, span := p.tracer.Start(ctx, "producer.sendEvent",
		trace.WithAttributes(
			attribute.String("event.type", eventType),
			attribute.String("topic", p.config.Topic),
		),
	)
	defer span.End()

	// Ensure metadata is set
	if err := p.ensureMetadata(event); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to ensure metadata: %w", err)
	}

	// Serialize the event
	data, err := proto.Marshal(event)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create headers
	headers := []kafka.Header{
		{Key: "event-type", Value: []byte(eventType)},
		{Key: "content-type", Value: []byte("application/x-protobuf")},
		{Key: "trace-id", Value: []byte(span.SpanContext().TraceID().String())},
	}

	// Create Kafka message
	message := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &p.config.Topic,
			Partition: kafka.PartitionAny,
		},
		Key:     []byte(p.extractEventKey(event)),
		Value:   data,
		Headers: headers,
	}

	// Send message
	select {
	case p.producer.ProduceChannel() <- message:
		p.metrics.MessagesSent++
		p.metrics.BytesSent += uint64(len(data))
		span.SetAttributes(
			attribute.Int("message.size", len(data)),
			attribute.String("message.key", string(message.Key)),
		)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ensureMetadata ensures event metadata is populated
func (p *Producer) ensureMetadata(event proto.Message) error {
	// Use reflection to find and set metadata field
	// This is a simplified version - in production, use proper reflection
	switch e := event.(type) {
	case *eventsv1.EmailReceived:
		if e.Metadata == nil {
			e.Metadata = &eventsv1.EventMetadata{}
		}
		p.populateMetadata(e.Metadata)
	case *eventsv1.EmailProcessed:
		if e.Metadata == nil {
			e.Metadata = &eventsv1.EventMetadata{}
		}
		p.populateMetadata(e.Metadata)
	case *eventsv1.EmailValidated:
		if e.Metadata == nil {
			e.Metadata = &eventsv1.EventMetadata{}
		}
		p.populateMetadata(e.Metadata)
	case *eventsv1.WorkflowTriggered:
		if e.Metadata == nil {
			e.Metadata = &eventsv1.EventMetadata{}
		}
		p.populateMetadata(e.Metadata)
	case *eventsv1.PluginExecutionRequired:
		if e.Metadata == nil {
			e.Metadata = &eventsv1.EventMetadata{}
		}
		p.populateMetadata(e.Metadata)
	default:
		return fmt.Errorf("unknown event type: %T", event)
	}
	return nil
}

// populateMetadata fills in missing metadata fields
func (p *Producer) populateMetadata(metadata *eventsv1.EventMetadata) {
	if metadata.EventId == "" {
		metadata.EventId = uuid.New().String()
	}
	if metadata.Timestamp == nil {
		metadata.Timestamp = timestamppb.Now()
	}
	if metadata.Source == "" {
		metadata.Source = "pat.producer"
	}
	if metadata.Attributes == nil {
		metadata.Attributes = make(map[string]string)
	}
}

// extractEventKey extracts a key from the event for partitioning
func (p *Producer) extractEventKey(event proto.Message) string {
	switch e := event.(type) {
	case *eventsv1.EmailReceived:
		return e.EmailId
	case *eventsv1.EmailProcessed:
		return e.EmailId
	case *eventsv1.EmailValidated:
		return e.EmailId
	case *eventsv1.WorkflowTriggered:
		return e.WorkflowId
	case *eventsv1.PluginExecutionRequired:
		return e.PluginId
	default:
		return uuid.New().String()
	}
}

// deliveryReportHandler handles delivery reports
func (p *Producer) deliveryReportHandler() {
	defer p.wg.Done()

	for {
		select {
		case ev := <-p.producer.Events():
			switch e := ev.(type) {
			case *kafka.Message:
				if e.TopicPartition.Error != nil {
					p.metrics.MessagesFailed++
					p.logger.Error("Failed to deliver message",
						zap.Error(e.TopicPartition.Error),
						zap.String("topic", *e.TopicPartition.Topic),
						zap.Int32("partition", e.TopicPartition.Partition),
					)
					p.errorCh <- e.TopicPartition.Error
				} else {
					p.metrics.MessagesDelivered++
					p.logger.Debug("Message delivered",
						zap.String("topic", *e.TopicPartition.Topic),
						zap.Int32("partition", e.TopicPartition.Partition),
						zap.Int64("offset", int64(e.TopicPartition.Offset)),
					)
				}
			case kafka.Error:
				p.logger.Error("Kafka error", zap.Error(e))
				p.errorCh <- e
			}
		case <-p.deliveryCh:
			return
		}
	}
}

// Flush waits for all messages to be delivered
func (p *Producer) Flush(ctx context.Context) error {
	ctx, span := p.tracer.Start(ctx, "producer.Flush")
	defer span.End()

	flushed := p.producer.Flush(int(p.config.FlushTimeout.Milliseconds()))
	if flushed > 0 {
		return fmt.Errorf("%d messages were not delivered", flushed)
	}
	return nil
}

// GetMetrics returns current producer metrics
func (p *Producer) GetMetrics() ProducerMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return *p.metrics
}

// Close closes the producer
func (p *Producer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Flush remaining messages
	p.producer.Flush(int(p.config.FlushTimeout.Milliseconds()))

	// Signal shutdown
	close(p.deliveryCh)

	// Wait for delivery handler to finish
	p.wg.Wait()

	// Close producer
	p.producer.Close()

	// Close channels
	close(p.errorCh)

	return nil
}