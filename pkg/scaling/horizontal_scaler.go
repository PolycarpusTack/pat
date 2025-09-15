package scaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HorizontalScaler provides automatic horizontal scaling capabilities for Pat Fortress
type HorizontalScaler struct {
	logger          *zap.Logger
	config          *ScalingConfig
	metrics         *ScalingMetrics
	scalingPolicies []*ScalingPolicy
	instances       map[string]*ServiceInstance
	mutex           sync.RWMutex
	shutdown        chan struct{}
	scaleEvents     chan ScaleEvent
}

// ScalingConfig defines horizontal scaling configuration
type ScalingConfig struct {
	// Scaling boundaries
	MinInstances int
	MaxInstances int
	
	// Scaling thresholds
	CPUThreshold     float64 // CPU utilization percentage (0-100)
	MemoryThreshold  float64 // Memory utilization percentage (0-100)
	QueueThreshold   int64   // Queue size threshold
	LatencyThreshold time.Duration // Response latency threshold
	
	// Scaling behavior
	ScaleUpCooldown   time.Duration
	ScaleDownCooldown time.Duration
	ScaleUpStep       int // Number of instances to add
	ScaleDownStep     int // Number of instances to remove
	
	// Evaluation
	EvaluationInterval time.Duration
	MetricsWindow      time.Duration
	
	// Service discovery
	ServiceDiscovery ServiceDiscovery
	LoadBalancer     LoadBalancer
}

// ServiceInstance represents a running service instance
type ServiceInstance struct {
	ID           string
	ServiceType  string
	Address      string
	Port         int
	Status       InstanceStatus
	StartedAt    time.Time
	LastHealthy  time.Time
	Metrics      InstanceMetrics
	Tags         map[string]string
}

// InstanceStatus represents the status of a service instance
type InstanceStatus int

const (
	StatusPending InstanceStatus = iota
	StatusHealthy
	StatusUnhealthy
	StatusTerminating
	StatusTerminated
)

// InstanceMetrics tracks metrics for a single instance
type InstanceMetrics struct {
	CPUUsage        float64
	MemoryUsage     float64
	QueueSize       int64
	RequestsPerSec  float64
	AverageLatency  time.Duration
	ErrorRate       float64
	ConnectionCount int64
	LastUpdated     time.Time
}

// ScalingMetrics tracks overall scaling metrics
type ScalingMetrics struct {
	mutex                sync.RWMutex
	TotalInstances       int
	HealthyInstances     int
	PendingInstances     int
	TerminatingInstances int
	ScaleUpEvents        int64
	ScaleDownEvents      int64
	LastScaleAction      time.Time
	AggregateMetrics     InstanceMetrics
}

// ScalingPolicy defines rules for when and how to scale
type ScalingPolicy struct {
	Name        string
	ServiceType string
	Conditions  []ScalingCondition
	Actions     []ScalingAction
	Priority    int
	Enabled     bool
}

// ScalingCondition defines a condition that triggers scaling
type ScalingCondition struct {
	Metric    string
	Operator  ComparisonOperator
	Threshold interface{}
	Duration  time.Duration
}

// ScalingAction defines an action to take when scaling
type ScalingAction struct {
	Type       ActionType
	Count      int
	Parameters map[string]interface{}
}

// ComparisonOperator defines comparison operators for scaling conditions
type ComparisonOperator int

const (
	GreaterThan ComparisonOperator = iota
	LessThan
	GreaterThanOrEqual
	LessThanOrEqual
	Equal
)

// ActionType defines the type of scaling action
type ActionType int

const (
	ActionScaleUp ActionType = iota
	ActionScaleDown
	ActionNotify
	ActionCustom
)

// ScaleEvent represents a scaling event
type ScaleEvent struct {
	Timestamp   time.Time
	EventType   string
	ServiceType string
	InstanceID  string
	Reason      string
	Metadata    map[string]interface{}
}

// ServiceDiscovery interface for service registration/discovery
type ServiceDiscovery interface {
	RegisterInstance(ctx context.Context, instance *ServiceInstance) error
	DeregisterInstance(ctx context.Context, instanceID string) error
	DiscoverInstances(ctx context.Context, serviceType string) ([]*ServiceInstance, error)
	HealthCheck(ctx context.Context, instanceID string) error
}

// LoadBalancer interface for load balancing
type LoadBalancer interface {
	AddInstance(ctx context.Context, instance *ServiceInstance) error
	RemoveInstance(ctx context.Context, instanceID string) error
	UpdateInstanceHealth(ctx context.Context, instanceID string, healthy bool) error
	GetInstanceMetrics(ctx context.Context, instanceID string) (*InstanceMetrics, error)
}

// NewHorizontalScaler creates a new horizontal scaler
func NewHorizontalScaler(logger *zap.Logger, config *ScalingConfig) *HorizontalScaler {
	if config == nil {
		config = DefaultScalingConfig()
	}
	
	scaler := &HorizontalScaler{
		logger:          logger,
		config:          config,
		metrics:         &ScalingMetrics{},
		scalingPolicies: make([]*ScalingPolicy, 0),
		instances:       make(map[string]*ServiceInstance),
		shutdown:        make(chan struct{}),
		scaleEvents:     make(chan ScaleEvent, 1000),
	}
	
	// Add default scaling policies
	scaler.addDefaultPolicies()
	
	logger.Info("HorizontalScaler initialized",
		zap.Int("min_instances", config.MinInstances),
		zap.Int("max_instances", config.MaxInstances),
		zap.Float64("cpu_threshold", config.CPUThreshold),
		zap.Float64("memory_threshold", config.MemoryThreshold),
	)
	
	return scaler
}

// DefaultScalingConfig returns sensible default scaling configuration
func DefaultScalingConfig() *ScalingConfig {
	return &ScalingConfig{
		MinInstances:       2,
		MaxInstances:       20,
		CPUThreshold:       70.0,  // 70% CPU utilization
		MemoryThreshold:    80.0,  // 80% memory utilization
		QueueThreshold:     1000,  // 1000 items in queue
		LatencyThreshold:   100 * time.Millisecond,
		ScaleUpCooldown:    5 * time.Minute,
		ScaleDownCooldown:  10 * time.Minute,
		ScaleUpStep:        2,  // Add 2 instances at a time
		ScaleDownStep:      1,  // Remove 1 instance at a time
		EvaluationInterval: 30 * time.Second,
		MetricsWindow:      5 * time.Minute,
	}
}

// Start begins the horizontal scaling process
func (hs *HorizontalScaler) Start(ctx context.Context) error {
	hs.logger.Info("Starting HorizontalScaler")
	
	// Start metrics collection
	go hs.metricsCollector(ctx)
	
	// Start scaling evaluator
	go hs.scalingEvaluator(ctx)
	
	// Start event processor
	go hs.eventProcessor(ctx)
	
	// Ensure minimum instances are running
	if err := hs.ensureMinimumInstances(ctx); err != nil {
		hs.logger.Error("Failed to ensure minimum instances", zap.Error(err))
		return err
	}
	
	hs.logger.Info("HorizontalScaler started successfully")
	return nil
}

// Stop gracefully stops the horizontal scaler
func (hs *HorizontalScaler) Stop(ctx context.Context) error {
	hs.logger.Info("Stopping HorizontalScaler")
	
	close(hs.shutdown)
	
	// Wait for ongoing scaling operations to complete
	select {
	case <-ctx.Done():
		hs.logger.Warn("HorizontalScaler shutdown timeout exceeded")
		return ctx.Err()
	case <-time.After(30 * time.Second):
		hs.logger.Info("HorizontalScaler stopped gracefully")
	}
	
	return nil
}

// AddScalingPolicy adds a custom scaling policy
func (hs *HorizontalScaler) AddScalingPolicy(policy *ScalingPolicy) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	
	hs.scalingPolicies = append(hs.scalingPolicies, policy)
	
	hs.logger.Info("Scaling policy added",
		zap.String("policy_name", policy.Name),
		zap.String("service_type", policy.ServiceType),
		zap.Int("priority", policy.Priority),
	)
}

// RegisterInstance registers a new service instance
func (hs *HorizontalScaler) RegisterInstance(ctx context.Context, instance *ServiceInstance) error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	
	instance.StartedAt = time.Now()
	instance.Status = StatusPending
	
	hs.instances[instance.ID] = instance
	
	// Register with service discovery
	if hs.config.ServiceDiscovery != nil {
		if err := hs.config.ServiceDiscovery.RegisterInstance(ctx, instance); err != nil {
			hs.logger.Error("Failed to register instance with service discovery",
				zap.String("instance_id", instance.ID),
				zap.Error(err),
			)
			return err
		}
	}
	
	// Add to load balancer
	if hs.config.LoadBalancer != nil {
		if err := hs.config.LoadBalancer.AddInstance(ctx, instance); err != nil {
			hs.logger.Error("Failed to add instance to load balancer",
				zap.String("instance_id", instance.ID),
				zap.Error(err),
			)
			return err
		}
	}
	
	hs.emitScaleEvent(ScaleEvent{
		Timestamp:   time.Now(),
		EventType:   "instance_registered",
		ServiceType: instance.ServiceType,
		InstanceID:  instance.ID,
		Reason:      "new_instance_registered",
	})
	
	hs.logger.Info("Instance registered",
		zap.String("instance_id", instance.ID),
		zap.String("service_type", instance.ServiceType),
		zap.String("address", fmt.Sprintf("%s:%d", instance.Address, instance.Port)),
	)
	
	return nil
}

// DeregisterInstance removes a service instance
func (hs *HorizontalScaler) DeregisterInstance(ctx context.Context, instanceID string) error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	
	instance, exists := hs.instances[instanceID]
	if !exists {
		return fmt.Errorf("instance not found: %s", instanceID)
	}
	
	instance.Status = StatusTerminating
	
	// Remove from load balancer
	if hs.config.LoadBalancer != nil {
		if err := hs.config.LoadBalancer.RemoveInstance(ctx, instanceID); err != nil {
			hs.logger.Error("Failed to remove instance from load balancer",
				zap.String("instance_id", instanceID),
				zap.Error(err),
			)
		}
	}
	
	// Deregister from service discovery
	if hs.config.ServiceDiscovery != nil {
		if err := hs.config.ServiceDiscovery.DeregisterInstance(ctx, instanceID); err != nil {
			hs.logger.Error("Failed to deregister instance from service discovery",
				zap.String("instance_id", instanceID),
				zap.Error(err),
			)
		}
	}
	
	instance.Status = StatusTerminated
	delete(hs.instances, instanceID)
	
	hs.emitScaleEvent(ScaleEvent{
		Timestamp:   time.Now(),
		EventType:   "instance_deregistered",
		ServiceType: instance.ServiceType,
		InstanceID:  instanceID,
		Reason:      "instance_terminated",
	})
	
	hs.logger.Info("Instance deregistered",
		zap.String("instance_id", instanceID),
		zap.String("service_type", instance.ServiceType),
	)
	
	return nil
}

// GetMetrics returns current scaling metrics
func (hs *HorizontalScaler) GetMetrics() ScalingMetrics {
	hs.metrics.mutex.RLock()
	defer hs.metrics.mutex.RUnlock()
	
	metrics := *hs.metrics
	
	// Update live instance counts
	hs.mutex.RLock()
	totalInstances := 0
	healthyInstances := 0
	pendingInstances := 0
	terminatingInstances := 0
	
	for _, instance := range hs.instances {
		totalInstances++
		switch instance.Status {
		case StatusHealthy:
			healthyInstances++
		case StatusPending:
			pendingInstances++
		case StatusTerminating:
			terminatingInstances++
		}
	}
	hs.mutex.RUnlock()
	
	metrics.TotalInstances = totalInstances
	metrics.HealthyInstances = healthyInstances
	metrics.PendingInstances = pendingInstances
	metrics.TerminatingInstances = terminatingInstances
	
	return metrics
}

// addDefaultPolicies adds default scaling policies
func (hs *HorizontalScaler) addDefaultPolicies() {
	// High CPU utilization policy
	cpuPolicy := &ScalingPolicy{
		Name:        "high_cpu_utilization",
		ServiceType: "smtp",
		Priority:    10,
		Enabled:     true,
		Conditions: []ScalingCondition{
			{
				Metric:    "cpu_usage",
				Operator:  GreaterThan,
				Threshold: hs.config.CPUThreshold,
				Duration:  2 * time.Minute,
			},
		},
		Actions: []ScalingAction{
			{
				Type:  ActionScaleUp,
				Count: hs.config.ScaleUpStep,
			},
		},
	}
	
	// High memory utilization policy
	memoryPolicy := &ScalingPolicy{
		Name:        "high_memory_utilization",
		ServiceType: "smtp",
		Priority:    10,
		Enabled:     true,
		Conditions: []ScalingCondition{
			{
				Metric:    "memory_usage",
				Operator:  GreaterThan,
				Threshold: hs.config.MemoryThreshold,
				Duration:  2 * time.Minute,
			},
		},
		Actions: []ScalingAction{
			{
				Type:  ActionScaleUp,
				Count: hs.config.ScaleUpStep,
			},
		},
	}
	
	// High queue size policy
	queuePolicy := &ScalingPolicy{
		Name:        "high_queue_size",
		ServiceType: "smtp",
		Priority:    15,
		Enabled:     true,
		Conditions: []ScalingCondition{
			{
				Metric:    "queue_size",
				Operator:  GreaterThan,
				Threshold: hs.config.QueueThreshold,
				Duration:  1 * time.Minute,
			},
		},
		Actions: []ScalingAction{
			{
				Type:  ActionScaleUp,
				Count: hs.config.ScaleUpStep,
			},
		},
	}
	
	// Low utilization scale-down policy
	scaleDownPolicy := &ScalingPolicy{
		Name:        "low_utilization",
		ServiceType: "smtp",
		Priority:    5,
		Enabled:     true,
		Conditions: []ScalingCondition{
			{
				Metric:    "cpu_usage",
				Operator:  LessThan,
				Threshold: 30.0, // Scale down if CPU < 30%
				Duration:  10 * time.Minute,
			},
			{
				Metric:    "queue_size",
				Operator:  LessThan,
				Threshold: int64(100), // And queue < 100
				Duration:  10 * time.Minute,
			},
		},
		Actions: []ScalingAction{
			{
				Type:  ActionScaleDown,
				Count: hs.config.ScaleDownStep,
			},
		},
	}
	
	hs.scalingPolicies = append(hs.scalingPolicies,
		cpuPolicy, memoryPolicy, queuePolicy, scaleDownPolicy)
}

// ensureMinimumInstances ensures minimum number of instances are running
func (hs *HorizontalScaler) ensureMinimumInstances(ctx context.Context) error {
	hs.mutex.RLock()
	currentCount := len(hs.instances)
	hs.mutex.RUnlock()
	
	if currentCount < hs.config.MinInstances {
		needed := hs.config.MinInstances - currentCount
		hs.logger.Info("Ensuring minimum instances",
			zap.Int("current", currentCount),
			zap.Int("minimum", hs.config.MinInstances),
			zap.Int("needed", needed),
		)
		
		return hs.scaleUp(ctx, "smtp", needed, "ensure_minimum_instances")
	}
	
	return nil
}

// metricsCollector collects and aggregates metrics from all instances
func (hs *HorizontalScaler) metricsCollector(ctx context.Context) {
	ticker := time.NewTicker(hs.config.EvaluationInterval / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			hs.collectMetrics(ctx)
		case <-ctx.Done():
			return
		case <-hs.shutdown:
			return
		}
	}
}

// scalingEvaluator evaluates scaling policies and triggers scaling actions
func (hs *HorizontalScaler) scalingEvaluator(ctx context.Context) {
	ticker := time.NewTicker(hs.config.EvaluationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			hs.evaluateScalingPolicies(ctx)
		case <-ctx.Done():
			return
		case <-hs.shutdown:
			return
		}
	}
}

// eventProcessor processes scaling events
func (hs *HorizontalScaler) eventProcessor(ctx context.Context) {
	for {
		select {
		case event := <-hs.scaleEvents:
			hs.processScaleEvent(event)
		case <-ctx.Done():
			return
		case <-hs.shutdown:
			return
		}
	}
}

// collectMetrics collects metrics from all instances
func (hs *HorizontalScaler) collectMetrics(ctx context.Context) {
	// Implementation would collect metrics from load balancer and service discovery
	// This is a simplified version
	
	hs.mutex.RLock()
	instanceCount := len(hs.instances)
	hs.mutex.RUnlock()
	
	if hs.config.LoadBalancer != nil && instanceCount > 0 {
		// Collect aggregate metrics (simplified)
		aggregateMetrics := InstanceMetrics{
			LastUpdated: time.Now(),
		}
		
		hs.metrics.mutex.Lock()
		hs.metrics.AggregateMetrics = aggregateMetrics
		hs.metrics.mutex.Unlock()
	}
}

// evaluateScalingPolicies evaluates all scaling policies and triggers actions
func (hs *HorizontalScaler) evaluateScalingPolicies(ctx context.Context) {
	for _, policy := range hs.scalingPolicies {
		if !policy.Enabled {
			continue
		}
		
		if hs.evaluatePolicy(policy) {
			hs.executeScalingActions(ctx, policy)
		}
	}
}

// evaluatePolicy evaluates a single scaling policy
func (hs *HorizontalScaler) evaluatePolicy(policy *ScalingPolicy) bool {
	// Simplified policy evaluation - in reality, this would be much more sophisticated
	metrics := hs.GetMetrics()
	
	for _, condition := range policy.Conditions {
		if !hs.evaluateCondition(condition, &metrics.AggregateMetrics) {
			return false
		}
	}
	
	return true
}

// evaluateCondition evaluates a single scaling condition
func (hs *HorizontalScaler) evaluateCondition(condition ScalingCondition, metrics *InstanceMetrics) bool {
	var actualValue float64
	
	switch condition.Metric {
	case "cpu_usage":
		actualValue = metrics.CPUUsage
	case "memory_usage":
		actualValue = metrics.MemoryUsage
	case "queue_size":
		actualValue = float64(metrics.QueueSize)
	default:
		return false
	}
	
	threshold, ok := condition.Threshold.(float64)
	if !ok {
		if intThreshold, ok := condition.Threshold.(int64); ok {
			threshold = float64(intThreshold)
		} else {
			return false
		}
	}
	
	switch condition.Operator {
	case GreaterThan:
		return actualValue > threshold
	case LessThan:
		return actualValue < threshold
	case GreaterThanOrEqual:
		return actualValue >= threshold
	case LessThanOrEqual:
		return actualValue <= threshold
	case Equal:
		return actualValue == threshold
	default:
		return false
	}
}

// executeScalingActions executes scaling actions for a policy
func (hs *HorizontalScaler) executeScalingActions(ctx context.Context, policy *ScalingPolicy) {
	for _, action := range policy.Actions {
		switch action.Type {
		case ActionScaleUp:
			hs.scaleUp(ctx, policy.ServiceType, action.Count, policy.Name)
		case ActionScaleDown:
			hs.scaleDown(ctx, policy.ServiceType, action.Count, policy.Name)
		case ActionNotify:
			hs.sendNotification(policy, action)
		}
	}
}

// scaleUp increases the number of instances
func (hs *HorizontalScaler) scaleUp(ctx context.Context, serviceType string, count int, reason string) error {
	metrics := hs.GetMetrics()
	
	if metrics.TotalInstances+count > hs.config.MaxInstances {
		hs.logger.Warn("Cannot scale up - would exceed maximum instances",
			zap.Int("current", metrics.TotalInstances),
			zap.Int("requested", count),
			zap.Int("maximum", hs.config.MaxInstances),
		)
		return fmt.Errorf("would exceed maximum instances")
	}
	
	// Check cooldown period
	if time.Since(hs.metrics.LastScaleAction) < hs.config.ScaleUpCooldown {
		hs.logger.Debug("Scale up skipped due to cooldown period",
			zap.Duration("time_since_last_scale", time.Since(hs.metrics.LastScaleAction)),
			zap.Duration("cooldown_period", hs.config.ScaleUpCooldown),
		)
		return nil
	}
	
	hs.logger.Info("Scaling up",
		zap.String("service_type", serviceType),
		zap.Int("count", count),
		zap.String("reason", reason),
	)
	
	// In a real implementation, this would trigger instance creation
	// For now, we'll just log and update metrics
	
	hs.metrics.mutex.Lock()
	hs.metrics.ScaleUpEvents++
	hs.metrics.LastScaleAction = time.Now()
	hs.metrics.mutex.Unlock()
	
	hs.emitScaleEvent(ScaleEvent{
		Timestamp:   time.Now(),
		EventType:   "scale_up",
		ServiceType: serviceType,
		Reason:      reason,
		Metadata: map[string]interface{}{
			"instance_count": count,
		},
	})
	
	return nil
}

// scaleDown decreases the number of instances
func (hs *HorizontalScaler) scaleDown(ctx context.Context, serviceType string, count int, reason string) error {
	metrics := hs.GetMetrics()
	
	if metrics.TotalInstances-count < hs.config.MinInstances {
		hs.logger.Debug("Cannot scale down - would go below minimum instances",
			zap.Int("current", metrics.TotalInstances),
			zap.Int("requested", count),
			zap.Int("minimum", hs.config.MinInstances),
		)
		return nil
	}
	
	// Check cooldown period
	if time.Since(hs.metrics.LastScaleAction) < hs.config.ScaleDownCooldown {
		hs.logger.Debug("Scale down skipped due to cooldown period",
			zap.Duration("time_since_last_scale", time.Since(hs.metrics.LastScaleAction)),
			zap.Duration("cooldown_period", hs.config.ScaleDownCooldown),
		)
		return nil
	}
	
	hs.logger.Info("Scaling down",
		zap.String("service_type", serviceType),
		zap.Int("count", count),
		zap.String("reason", reason),
	)
	
	// In a real implementation, this would trigger instance termination
	// For now, we'll just log and update metrics
	
	hs.metrics.mutex.Lock()
	hs.metrics.ScaleDownEvents++
	hs.metrics.LastScaleAction = time.Now()
	hs.metrics.mutex.Unlock()
	
	hs.emitScaleEvent(ScaleEvent{
		Timestamp:   time.Now(),
		EventType:   "scale_down",
		ServiceType: serviceType,
		Reason:      reason,
		Metadata: map[string]interface{}{
			"instance_count": count,
		},
	})
	
	return nil
}

// sendNotification sends a scaling notification
func (hs *HorizontalScaler) sendNotification(policy *ScalingPolicy, action ScalingAction) {
	hs.logger.Info("Scaling notification",
		zap.String("policy", policy.Name),
		zap.Any("action", action),
	)
}

// emitScaleEvent emits a scaling event
func (hs *HorizontalScaler) emitScaleEvent(event ScaleEvent) {
	select {
	case hs.scaleEvents <- event:
	default:
		hs.logger.Warn("Scale event queue full, dropping event")
	}
}

// processScaleEvent processes a scaling event
func (hs *HorizontalScaler) processScaleEvent(event ScaleEvent) {
	hs.logger.Debug("Processing scale event",
		zap.String("event_type", event.EventType),
		zap.String("service_type", event.ServiceType),
		zap.String("reason", event.Reason),
	)
	
	// In a real implementation, this would handle event persistence,
	// alerting, metrics updates, etc.
}