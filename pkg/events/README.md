# Pat Events Package

This package provides high-performance event publishing and consumption for the Pat email testing platform.

## Features

- **High Performance**: Capable of handling 10,000+ events/second
- **Multiple Formats**: Support for Protobuf and Avro schemas
- **Retry Logic**: Exponential backoff with dead letter queue support
- **Observability**: OpenTelemetry tracing and comprehensive metrics
- **Security**: IAM/SASL authentication, TLS encryption
- **Resilience**: Automatic reconnection, consumer group management

## Usage

### Producer

```go
import (
    "github.com/pat/pkg/events"
    eventsv1 "github.com/pat/api/events/v1"
)

// Create producer
config := events.ProducerConfig{
    Brokers:          []string{"localhost:9092"},
    Topic:            "pat-events",
    CompressionType:  "lz4",
    IdempotenceEnable: true,
}

producer, err := events.NewProducer(config, logger)
if err != nil {
    log.Fatal(err)
}
defer producer.Close()

// Send event
event := &eventsv1.EmailReceived{
    EmailId:   "123",
    MessageId: "<123@example.com>",
    From:      &eventsv1.EmailAddress{Address: "sender@example.com"},
    // ... other fields
}

err = producer.SendEmailReceived(ctx, event)
if err != nil {
    log.Error("Failed to send event", err)
}

// Flush before shutdown
producer.Flush(ctx)
```

### Consumer

```go
// Implement event handler
type MyHandler struct{}

func (h *MyHandler) HandleEmailReceived(ctx context.Context, event *eventsv1.EmailReceived) error {
    log.Info("Received email", event.EmailId)
    // Process email...
    return nil
}

// ... implement other handler methods

// Create consumer
config := events.ConsumerConfig{
    Brokers:  []string{"localhost:9092"},
    Topics:   []string{"pat-events"},
    GroupID:  "my-consumer-group",
}

handler := &MyHandler{}
consumer, err := events.NewConsumer(config, handler, logger)
if err != nil {
    log.Fatal(err)
}
defer consumer.Close()

// Start consuming
if err := consumer.Start(ctx); err != nil {
    log.Fatal(err)
}

// Stop gracefully
consumer.Stop(ctx)
```

## Event Types

- **EmailReceived**: New email arrived via any protocol
- **EmailProcessed**: Email processing completed
- **EmailValidated**: Email validation results
- **WorkflowTriggered**: Workflow execution started
- **PluginExecutionRequired**: Plugin needs to be executed
- **PluginExecutionCompleted**: Plugin execution finished
- **EmailDeleted**: Email was deleted
- **TenantEvent**: Multi-tenant operations

## Performance

The package is designed to handle high throughput:

- Producer: 10,000+ events/second
- Consumer: 10,000+ events/second with <100ms lag
- Batching and compression for efficiency
- Connection pooling and pipelining

## Configuration

### Producer Options

| Option | Default | Description |
|--------|---------|-------------|
| BatchSize | 100 | Messages per batch |
| FlushTimeout | 5s | Max time before flush |
| CompressionType | none | lz4, snappy, gzip, zstd |
| IdempotenceEnable | false | Enable idempotent producer |

### Consumer Options

| Option | Default | Description |
|--------|---------|-------------|
| AutoOffsetReset | latest | earliest, latest, none |
| SessionTimeout | 10s | Consumer group timeout |
| MaxPollInterval | 5m | Max time between polls |
| EnableAutoCommit | false | Auto-commit offsets |

## Monitoring

Metrics are exposed via the `GetMetrics()` method:

```go
metrics := producer.GetMetrics()
log.Info("Producer metrics",
    "sent", metrics.MessagesSent,
    "delivered", metrics.MessagesDelivered,
    "failed", metrics.MessagesFailed,
)
```

## Testing

Run unit tests:
```bash
go test ./pkg/events
```

Run performance tests:
```bash
go test ./pkg/events -run TestProducerPerformance -v
```

## Schema Evolution

The package supports schema evolution:

1. Always add new fields as optional
2. Never remove or rename existing fields
3. Use field deprecation for old fields
4. Test compatibility before deployment