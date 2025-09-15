package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// EventBusService implements the EventBus interface for inter-service communication
type EventBusService struct {
	config     *Config
	foundation interfaces.Foundation
	watchtower interfaces.Watchtower
	logger     *zap.Logger

	// Event handling
	subscribers map[string][]interfaces.EventHandler
	eventQueue  chan *interfaces.Event
	workers     []*EventWorker
	
	// Service state
	mu        sync.RWMutex
	started   bool
	stopping  bool
	workerStop chan struct{}
	
	// Event persistence
	persistEvents bool
	eventHistory  []*interfaces.Event
	historyMu     sync.RWMutex
}

// Config contains EventBus service configuration
type Config struct {
	Driver             string   `json:"driver"`
	BufferSize         int      `json:"bufferSize"`
	WorkerCount        int      `json:"workerCount"`
	MaxRetries         int      `json:"maxRetries"`
	RetryDelay         time.Duration `json:"retryDelay"`
	PersistEvents      bool     `json:"persistEvents"`
	EventRetentionDays int      `json:"eventRetentionDays"`
	ExternalBrokers    []string `json:"externalBrokers"`
}

// EventWorker processes events from the queue
type EventWorker struct {
	ID      int
	service *EventBusService
	logger  *zap.Logger
}

// NewEventBusService creates a new EventBus service instance
func NewEventBusService(ctx context.Context, config *Config, foundation interfaces.Foundation, watchtower interfaces.Watchtower, logger *zap.Logger) (*EventBusService, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	service := &EventBusService{
		config:      config,
		foundation:  foundation,
		watchtower:  watchtower,
		logger:      logger.Named("eventbus"),
		subscribers: make(map[string][]interfaces.EventHandler),
		eventQueue:  make(chan *interfaces.Event, config.BufferSize),
		workerStop:  make(chan struct{}),
		persistEvents: config.PersistEvents,
		eventHistory:  make([]*interfaces.Event, 0),
	}

	logger.Info("EventBus service created successfully")
	return service, nil
}

// Publish publishes an event synchronously
func (e *EventBusService) Publish(ctx context.Context, event *interfaces.Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	e.logger.Debug("Publishing event",
		zap.String("type", event.Type),
		zap.String("source", event.Source),
		zap.String("id", event.ID))

	// Validate event
	if err := e.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Ensure event has required fields
	if event.ID == "" {
		event.ID = e.generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Record event metrics
	e.watchtower.IncrementCounter("eventbus.events.published", map[string]string{
		"event_type":   event.Type,
		"event_source": event.Source,
	})

	// Process event synchronously
	return e.processEvent(ctx, event)
}

// PublishAsync publishes an event asynchronously
func (e *EventBusService) PublishAsync(ctx context.Context, event *interfaces.Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	e.logger.Debug("Publishing event asynchronously",
		zap.String("type", event.Type),
		zap.String("source", event.Source),
		zap.String("id", event.ID))

	// Validate event
	if err := e.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Ensure event has required fields
	if event.ID == "" {
		event.ID = e.generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Queue event for asynchronous processing
	select {
	case e.eventQueue <- event:
		e.watchtower.IncrementCounter("eventbus.events.queued", map[string]string{
			"event_type":   event.Type,
			"event_source": event.Source,
		})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Queue is full, try to process synchronously as fallback
		e.logger.Warn("Event queue full, processing synchronously",
			zap.String("event_id", event.ID))
		e.watchtower.IncrementCounter("eventbus.queue.full", map[string]string{
			"event_type": event.Type,
		})
		return e.processEvent(ctx, event)
	}
}

// Subscribe subscribes a handler to events of a specific type
func (e *EventBusService) Subscribe(eventType string, handler interfaces.EventHandler) error {
	if eventType == "" {
		return fmt.Errorf("event type cannot be empty")
	}
	if handler == nil {
		return fmt.Errorf("event handler cannot be nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.subscribers[eventType] == nil {
		e.subscribers[eventType] = make([]interfaces.EventHandler, 0)
	}

	e.subscribers[eventType] = append(e.subscribers[eventType], handler)

	e.logger.Info("Event handler subscribed",
		zap.String("event_type", eventType),
		zap.Int("handler_count", len(e.subscribers[eventType])))

	e.watchtower.IncrementCounter("eventbus.subscriptions.added", map[string]string{
		"event_type": eventType,
	})

	return nil
}

// Unsubscribe removes a handler from event subscriptions
func (e *EventBusService) Unsubscribe(eventType string, handler interfaces.EventHandler) error {
	if eventType == "" {
		return fmt.Errorf("event type cannot be empty")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	handlers, exists := e.subscribers[eventType]
	if !exists {
		return fmt.Errorf("no subscriptions found for event type: %s", eventType)
	}

	// Remove handler from slice (simplified implementation)
	newHandlers := make([]interfaces.EventHandler, 0, len(handlers))
	removed := false
	for _, h := range handlers {
		if fmt.Sprintf("%p", h) != fmt.Sprintf("%p", handler) {
			newHandlers = append(newHandlers, h)
		} else {
			removed = true
		}
	}

	if !removed {
		return fmt.Errorf("handler not found for event type: %s", eventType)
	}

	e.subscribers[eventType] = newHandlers

	e.logger.Info("Event handler unsubscribed",
		zap.String("event_type", eventType),
		zap.Int("remaining_handlers", len(newHandlers)))

	e.watchtower.IncrementCounter("eventbus.subscriptions.removed", map[string]string{
		"event_type": eventType,
	})

	return nil
}

// ListSubscriptions returns a list of all event types with active subscriptions
func (e *EventBusService) ListSubscriptions(ctx context.Context) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	eventTypes := make([]string, 0, len(e.subscribers))
	for eventType, handlers := range e.subscribers {
		if len(handlers) > 0 {
			eventTypes = append(eventTypes, eventType)
		}
	}

	return eventTypes, nil
}

// GetEventHistory returns filtered event history
func (e *EventBusService) GetEventHistory(ctx context.Context, filter *interfaces.EventFilter) ([]*interfaces.Event, error) {
	if !e.persistEvents {
		return nil, fmt.Errorf("event persistence is disabled")
	}

	e.historyMu.RLock()
	defer e.historyMu.RUnlock()

	// Apply filter
	filteredEvents := e.applyEventFilter(e.eventHistory, filter)

	e.logger.Debug("Retrieved event history",
		zap.Int("total_events", len(e.eventHistory)),
		zap.Int("filtered_events", len(filteredEvents)))

	return filteredEvents, nil
}

// Start starts the EventBus service
func (e *EventBusService) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.started {
		return fmt.Errorf("eventbus service already started")
	}

	e.logger.Info("Starting EventBus service")

	// Start event workers
	e.workers = make([]*EventWorker, e.config.WorkerCount)
	for i := 0; i < e.config.WorkerCount; i++ {
		worker := &EventWorker{
			ID:      i,
			service: e,
			logger:  e.logger.Named(fmt.Sprintf("worker-%d", i)),
		}
		e.workers[i] = worker
		go worker.Start(ctx, e.eventQueue, e.workerStop)
	}

	// Start event cleanup if persistence is enabled
	if e.persistEvents {
		go e.runEventCleanup(ctx)
	}

	// Start external broker connections if configured
	if len(e.config.ExternalBrokers) > 0 {
		go e.connectToExternalBrokers(ctx)
	}

	e.started = true
	e.logger.Info("EventBus service started successfully")
	return nil
}

// Stop stops the EventBus service
func (e *EventBusService) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.started || e.stopping {
		return fmt.Errorf("eventbus service not started or already stopping")
	}

	e.stopping = true
	e.logger.Info("Stopping EventBus service")

	// Stop workers
	close(e.workerStop)

	// Wait for workers to finish processing
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Wait for all workers to finish
		time.Sleep(5 * time.Second) // Simplified - would use proper synchronization
	}()

	select {
	case <-done:
		e.logger.Info("All event workers stopped")
	case <-time.After(30 * time.Second):
		e.logger.Warn("Timeout waiting for event workers to stop")
	}

	e.started = false
	e.stopping = false
	e.logger.Info("EventBus service stopped")
	return nil
}

// Health returns the health status of the EventBus service
func (e *EventBusService) Health(ctx context.Context) *interfaces.HealthStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &interfaces.HealthStatus{
		Service:   "eventbus",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if !e.started {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = "Service not started"
		return status
	}

	// Check queue status
	queueSize := len(e.eventQueue)
	queueCapacity := cap(e.eventQueue)
	queueUtilization := float64(queueSize) / float64(queueCapacity)

	status.Details["queue_size"] = queueSize
	status.Details["queue_capacity"] = queueCapacity
	status.Details["queue_utilization"] = queueUtilization
	status.Details["worker_count"] = len(e.workers)
	status.Details["subscriber_count"] = len(e.subscribers)

	// Determine health status
	if queueUtilization > 0.9 {
		status.Status = interfaces.HealthStatusDegraded
		status.Message = "Event queue nearly full"
	} else if queueUtilization > 0.95 {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = "Event queue critical"
	} else {
		status.Status = interfaces.HealthStatusHealthy
		status.Message = "Event bus operational"
	}

	return status
}

// Private helper methods

func (e *EventBusService) validateEvent(event *interfaces.Event) error {
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if event.Source == "" {
		return fmt.Errorf("event source is required")
	}
	return nil
}

func (e *EventBusService) processEvent(ctx context.Context, event *interfaces.Event) error {
	startTime := time.Now()

	// Store event if persistence is enabled
	if e.persistEvents {
		e.storeEvent(event)
	}

	// Get subscribers for this event type
	e.mu.RLock()
	handlers, exists := e.subscribers[event.Type]
	if !exists || len(handlers) == 0 {
		e.mu.RUnlock()
		e.logger.Debug("No subscribers for event type",
			zap.String("event_type", event.Type),
			zap.String("event_id", event.ID))
		return nil
	}

	// Make a copy of handlers to avoid holding the lock during processing
	handlersCopy := make([]interfaces.EventHandler, len(handlers))
	copy(handlersCopy, handlers)
	e.mu.RUnlock()

	// Process event with all handlers
	var lastError error
	successCount := 0
	
	for _, handler := range handlersCopy {
		if err := e.callHandler(ctx, handler, event); err != nil {
			e.logger.Error("Event handler failed",
				zap.String("event_type", event.Type),
				zap.String("event_id", event.ID),
				zap.Error(err))
			lastError = err
			
			e.watchtower.IncrementCounter("eventbus.handler.errors", map[string]string{
				"event_type": event.Type,
			})
		} else {
			successCount++
		}
	}

	// Record processing metrics
	duration := time.Since(startTime)
	e.watchtower.RecordHistogram("eventbus.event.processing.duration", duration.Seconds(), map[string]string{
		"event_type": event.Type,
	})

	e.watchtower.IncrementCounter("eventbus.events.processed", map[string]string{
		"event_type": event.Type,
		"success":    fmt.Sprintf("%t", lastError == nil),
	})

	e.logger.Debug("Event processed",
		zap.String("event_type", event.Type),
		zap.String("event_id", event.ID),
		zap.Int("handlers_called", len(handlersCopy)),
		zap.Int("successful_handlers", successCount),
		zap.Duration("duration", duration))

	return lastError
}

func (e *EventBusService) callHandler(ctx context.Context, handler interfaces.EventHandler, event *interfaces.Event) error {
	// Create timeout context for handler execution
	handlerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Call handler with recovery
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("Event handler panicked",
				zap.String("event_type", event.Type),
				zap.String("event_id", event.ID),
				zap.Any("panic", r))
		}
	}()

	return handler(handlerCtx, event)
}

func (e *EventBusService) storeEvent(event *interfaces.Event) {
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	e.eventHistory = append(e.eventHistory, event)

	// Keep history bounded
	maxHistory := 10000
	if len(e.eventHistory) > maxHistory {
		e.eventHistory = e.eventHistory[maxHistory/2:]
	}
}

func (e *EventBusService) applyEventFilter(events []*interfaces.Event, filter *interfaces.EventFilter) []*interfaces.Event {
	if filter == nil {
		return events
	}

	filtered := make([]*interfaces.Event, 0)
	
	for _, event := range events {
		// Apply type filter
		if len(filter.Types) > 0 {
			typeMatch := false
			for _, eventType := range filter.Types {
				if event.Type == eventType {
					typeMatch = true
					break
				}
			}
			if !typeMatch {
				continue
			}
		}

		// Apply source filter
		if len(filter.Sources) > 0 {
			sourceMatch := false
			for _, source := range filter.Sources {
				if event.Source == source {
					sourceMatch = true
					break
				}
			}
			if !sourceMatch {
				continue
			}
		}

		// Apply date filters
		if !filter.DateFrom.IsZero() && event.Timestamp.Before(filter.DateFrom) {
			continue
		}
		if !filter.DateTo.IsZero() && event.Timestamp.After(filter.DateTo) {
			continue
		}

		// Apply user filter
		if filter.UserID != "" && event.UserID != filter.UserID {
			continue
		}

		// Apply trace filter
		if filter.TraceID != "" && event.TraceID != filter.TraceID {
			continue
		}

		filtered = append(filtered, event)
	}

	// Apply limit and offset
	if filter.Offset > 0 && filter.Offset < len(filtered) {
		filtered = filtered[filter.Offset:]
	}

	if filter.Limit > 0 && filter.Limit < len(filtered) {
		filtered = filtered[:filter.Limit]
	}

	return filtered
}

func (e *EventBusService) runEventCleanup(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Daily cleanup
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.cleanupOldEvents()
		}
	}
}

func (e *EventBusService) cleanupOldEvents() {
	cutoffTime := time.Now().AddDate(0, 0, -e.config.EventRetentionDays)
	
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	originalCount := len(e.eventHistory)
	cleanedEvents := make([]*interfaces.Event, 0)

	for _, event := range e.eventHistory {
		if event.Timestamp.After(cutoffTime) {
			cleanedEvents = append(cleanedEvents, event)
		}
	}

	e.eventHistory = cleanedEvents
	cleanedCount := originalCount - len(cleanedEvents)

	e.logger.Info("Event cleanup completed",
		zap.Int("original_count", originalCount),
		zap.Int("cleaned_count", cleanedCount),
		zap.Int("remaining_count", len(cleanedEvents)))
}

func (e *EventBusService) connectToExternalBrokers(ctx context.Context) {
	// Implementation would connect to external message brokers
	// (Kafka, RabbitMQ, Redis, etc.)
	for _, broker := range e.config.ExternalBrokers {
		e.logger.Info("Connecting to external broker", zap.String("broker", broker))
		// Connect and set up message forwarding
	}
}

func (e *EventBusService) generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
}

// EventWorker implementation

// Start starts the event worker to process events from the queue
func (w *EventWorker) Start(ctx context.Context, eventQueue <-chan *interfaces.Event, stopChan <-chan struct{}) {
	w.logger.Info("Event worker starting", zap.Int("worker_id", w.ID))

	defer w.logger.Info("Event worker stopped", zap.Int("worker_id", w.ID))

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Event worker stopping due to context cancellation", zap.Int("worker_id", w.ID))
			return
		case <-stopChan:
			w.logger.Info("Event worker stopping due to stop signal", zap.Int("worker_id", w.ID))
			return
		case event := <-eventQueue:
			if event == nil {
				continue
			}
			w.processEvent(ctx, event)
		}
	}
}

func (w *EventWorker) processEvent(ctx context.Context, event *interfaces.Event) {
	w.logger.Debug("Processing event",
		zap.Int("worker_id", w.ID),
		zap.String("event_type", event.Type),
		zap.String("event_id", event.ID))

	startTime := time.Now()

	// Process the event
	err := w.service.processEvent(ctx, event)

	duration := time.Since(startTime)

	if err != nil {
		w.logger.Error("Event processing failed",
			zap.Int("worker_id", w.ID),
			zap.String("event_id", event.ID),
			zap.Error(err))

		// Implement retry logic if needed
		w.retryEvent(ctx, event, err)
	} else {
		w.logger.Debug("Event processed successfully",
			zap.Int("worker_id", w.ID),
			zap.String("event_id", event.ID),
			zap.Duration("duration", duration))
	}
}

func (w *EventWorker) retryEvent(ctx context.Context, event *interfaces.Event, lastError error) {
	// Simplified retry implementation
	// In production, would implement exponential backoff, dead letter queue, etc.
	retryCount := 0
	maxRetries := w.service.config.MaxRetries

	if retryCount < maxRetries {
		w.logger.Info("Retrying event processing",
			zap.String("event_id", event.ID),
			zap.Int("retry", retryCount+1),
			zap.Error(lastError))

		time.Sleep(w.service.config.RetryDelay)

		// Retry the event (simplified - would implement proper retry queue)
		go func() {
			select {
			case w.service.eventQueue <- event:
				w.logger.Debug("Event requeued for retry", zap.String("event_id", event.ID))
			default:
				w.logger.Error("Failed to requeue event for retry", zap.String("event_id", event.ID))
			}
		}()
	}
}