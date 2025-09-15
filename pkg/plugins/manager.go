package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// Manager orchestrates plugin lifecycle and execution
type Manager struct {
	registry    *Registry
	runtime     *PluginRuntime
	security    *SecurityScanner
	eventBus    EventBus
	metrics     MetricsCollector
	logger      Logger
	
	// Plugin instances
	instances   map[string]*PluginInstance
	instancesMu sync.RWMutex
	
	// Hook subscriptions
	hooks       map[string][]string // hook -> []pluginID
	hooksMu     sync.RWMutex
	
	// Configuration
	config      *ManagerConfig
}

// ManagerConfig contains configuration for the plugin manager
type ManagerConfig struct {
	MaxConcurrentExecutions int           `json:"max_concurrent_executions"`
	ExecutionTimeout        time.Duration `json:"execution_timeout"`
	MaxPluginsPerTenant     int           `json:"max_plugins_per_tenant"`
	EnableSandbox           bool          `json:"enable_sandbox"`
	EnableMetrics           bool          `json:"enable_metrics"`
	MemoryLimitMB           int           `json:"memory_limit_mb"`
	CPUTimeLimitMS          int           `json:"cpu_time_limit_ms"`
}

// PluginInstance represents a loaded plugin instance
type PluginInstance struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	PluginID      string                 `json:"plugin_id"`
	Version       string                 `json:"version"`
	Metadata      *PluginMetadata        `json:"metadata"`
	Code          string                 `json:"code"`
	Config        map[string]interface{} `json:"config"`
	State         PluginState            `json:"state"`
	LoadedAt      time.Time              `json:"loaded_at"`
	LastExecution time.Time              `json:"last_execution"`
	ExecutionCount int64                 `json:"execution_count"`
	ErrorCount     int64                 `json:"error_count"`
	mu            sync.RWMutex
}

// PluginState represents plugin instance state
type PluginState string

const (
	PluginStateLoading  PluginState = "loading"
	PluginStateReady    PluginState = "ready"
	PluginStateError    PluginState = "error"
	PluginStateStopped  PluginState = "stopped"
)

// ExecutionContext contains context for plugin execution
type ExecutionContext struct {
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id"`
	RequestID     string                 `json:"request_id"`
	Hook          string                 `json:"hook"`
	Payload       map[string]interface{} `json:"payload"`
	Metadata      map[string]interface{} `json:"metadata"`
	Timestamp     time.Time              `json:"timestamp"`
}

// NewManager creates a new plugin manager
func NewManager(
	registry *Registry,
	runtime *PluginRuntime,
	security *SecurityScanner,
	eventBus EventBus,
	metrics MetricsCollector,
	logger Logger,
	config *ManagerConfig,
) *Manager {
	return &Manager{
		registry:  registry,
		runtime:   runtime,
		security:  security,
		eventBus:  eventBus,
		metrics:   metrics,
		logger:    logger,
		instances: make(map[string]*PluginInstance),
		hooks:     make(map[string][]string),
		config:    config,
	}
}

// LoadPlugin loads a plugin for a tenant
func (m *Manager) LoadPlugin(ctx context.Context, tenantID, pluginID, version string) error {
	m.instancesMu.Lock()
	defer m.instancesMu.Unlock()

	instanceID := fmt.Sprintf("%s:%s:%s", tenantID, pluginID, version)
	
	// Check if already loaded
	if instance, exists := m.instances[instanceID]; exists {
		if instance.State == PluginStateReady {
			return nil
		}
	}

	// Get plugin metadata
	metadata, err := m.registry.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "failed to get plugin metadata")
	}

	// Get plugin code
	pluginCode, err := m.registry.GetPluginCode(ctx, pluginID, version)
	if err != nil {
		return errors.Wrap(err, "failed to get plugin code")
	}

	// Get plugin installation config
	installation, err := m.registry.GetPluginInstallation(ctx, tenantID, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not installed for tenant")
	}

	if !installation.Enabled {
		return errors.New("plugin is disabled")
	}

	// Create plugin instance
	instance := &PluginInstance{
		ID:             instanceID,
		TenantID:       tenantID,
		PluginID:       pluginID,
		Version:        version,
		Metadata:       metadata,
		Code:           pluginCode.Code,
		Config:         installation.Config,
		State:          PluginStateLoading,
		LoadedAt:       time.Now(),
		ExecutionCount: 0,
		ErrorCount:     0,
	}

	m.instances[instanceID] = instance

	// Create runtime isolate
	err = m.runtime.CreateIsolate(instanceID, metadata)
	if err != nil {
		instance.State = PluginStateError
		return errors.Wrap(err, "failed to create plugin isolate")
	}

	// Register hooks
	m.registerPluginHooks(instance)

	instance.State = PluginStateReady

	m.logger.Info("Plugin loaded successfully", map[string]interface{}{
		"tenant_id":   tenantID,
		"plugin_id":   pluginID,
		"version":     version,
		"instance_id": instanceID,
	})

	// Emit plugin loaded event
	m.eventBus.Publish("plugin.loaded", map[string]interface{}{
		"tenant_id":   tenantID,
		"plugin_id":   pluginID,
		"version":     version,
		"instance_id": instanceID,
	})

	return nil
}

// UnloadPlugin unloads a plugin instance
func (m *Manager) UnloadPlugin(ctx context.Context, tenantID, pluginID, version string) error {
	m.instancesMu.Lock()
	defer m.instancesMu.Unlock()

	instanceID := fmt.Sprintf("%s:%s:%s", tenantID, pluginID, version)
	
	instance, exists := m.instances[instanceID]
	if !exists {
		return errors.New("plugin instance not found")
	}

	// Unregister hooks
	m.unregisterPluginHooks(instance)

	// Dispose runtime isolate
	err := m.runtime.DisposePlugin(instanceID)
	if err != nil {
		m.logger.Warn("Failed to dispose plugin isolate", map[string]interface{}{
			"instance_id": instanceID,
			"error":       err.Error(),
		})
	}

	// Remove instance
	delete(m.instances, instanceID)

	m.logger.Info("Plugin unloaded", map[string]interface{}{
		"tenant_id":   tenantID,
		"plugin_id":   pluginID,
		"version":     version,
		"instance_id": instanceID,
	})

	// Emit plugin unloaded event
	m.eventBus.Publish("plugin.unloaded", map[string]interface{}{
		"tenant_id":   tenantID,
		"plugin_id":   pluginID,
		"version":     version,
		"instance_id": instanceID,
	})

	return nil
}

// ExecuteHook executes all plugins subscribed to a hook
func (m *Manager) ExecuteHook(ctx context.Context, hook string, execCtx *ExecutionContext) error {
	m.hooksMu.RLock()
	pluginIDs := make([]string, len(m.hooks[hook]))
	copy(pluginIDs, m.hooks[hook])
	m.hooksMu.RUnlock()

	if len(pluginIDs) == 0 {
		m.logger.Debug("No plugins subscribed to hook", map[string]interface{}{
			"hook":      hook,
			"tenant_id": execCtx.TenantID,
		})
		return nil
	}

	// Execute plugins concurrently
	semaphore := make(chan struct{}, m.config.MaxConcurrentExecutions)
	results := make(chan error, len(pluginIDs))

	for _, instanceID := range pluginIDs {
		go func(id string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			err := m.executePluginHook(ctx, id, hook, execCtx)
			results <- err
		}(instanceID)
	}

	// Collect results
	var errors []error
	for i := 0; i < len(pluginIDs); i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("hook execution failed for %d plugins: %v", len(errors), errors)
	}

	return nil
}

// executePluginHook executes a specific plugin for a hook
func (m *Manager) executePluginHook(ctx context.Context, instanceID, hook string, execCtx *ExecutionContext) error {
	m.instancesMu.RLock()
	instance, exists := m.instances[instanceID]
	m.instancesMu.RUnlock()

	if !exists {
		return fmt.Errorf("plugin instance not found: %s", instanceID)
	}

	if instance.State != PluginStateReady {
		return fmt.Errorf("plugin not ready: %s", instanceID)
	}

	// Check if plugin has this hook
	hasHook := false
	for _, h := range instance.Metadata.Hooks {
		if h == hook {
			hasHook = true
			break
		}
	}

	if !hasHook {
		return nil // Plugin doesn't handle this hook
	}

	// Create execution context
	pluginCtx := &PluginContext{
		TenantID: execCtx.TenantID,
		UserID:   execCtx.UserID,
		Email:    execCtx.Payload["email"],
		Metadata: *instance.Metadata,
	}

	// Execute plugin
	startTime := time.Now()
	result, err := m.runtime.ExecutePlugin(
		instanceID,
		instance.Code,
		"main",
		[]interface{}{hook, execCtx.Payload},
		*pluginCtx,
	)
	executionTime := time.Since(startTime)

	// Update instance stats
	instance.mu.Lock()
	instance.LastExecution = time.Now()
	instance.ExecutionCount++
	if err != nil || !result.Success {
		instance.ErrorCount++
	}
	instance.mu.Unlock()

	// Record metrics
	if m.config.EnableMetrics {
		m.metrics.RecordPluginExecution(instanceID, PluginExecutionMetrics{
			Hook:          hook,
			Success:       result.Success,
			ExecutionTime: executionTime,
			MemoryUsed:    result.Metrics.MemoryUsed,
			CPUTime:       time.Duration(result.Metrics.CPUTime) * time.Millisecond,
		})
	}

	// Log execution
	m.logger.Debug("Plugin hook executed", map[string]interface{}{
		"instance_id":    instanceID,
		"hook":           hook,
		"success":        result.Success,
		"execution_time": executionTime.Milliseconds(),
		"memory_used":    result.Metrics.MemoryUsed,
		"cpu_time":       result.Metrics.CPUTime,
	})

	if !result.Success {
		return fmt.Errorf("plugin execution failed: %s", result.Error)
	}

	// Emit execution event
	m.eventBus.Publish("plugin.executed", map[string]interface{}{
		"instance_id":    instanceID,
		"hook":           hook,
		"tenant_id":      execCtx.TenantID,
		"execution_time": executionTime.Milliseconds(),
		"success":        result.Success,
	})

	return nil
}

// GetPluginInstances returns all loaded plugin instances for a tenant
func (m *Manager) GetPluginInstances(tenantID string) []*PluginInstance {
	m.instancesMu.RLock()
	defer m.instancesMu.RUnlock()

	var instances []*PluginInstance
	for _, instance := range m.instances {
		if instance.TenantID == tenantID {
			instances = append(instances, instance)
		}
	}

	return instances
}

// GetPluginInstance returns a specific plugin instance
func (m *Manager) GetPluginInstance(tenantID, pluginID, version string) (*PluginInstance, error) {
	m.instancesMu.RLock()
	defer m.instancesMu.RUnlock()

	instanceID := fmt.Sprintf("%s:%s:%s", tenantID, pluginID, version)
	instance, exists := m.instances[instanceID]
	if !exists {
		return nil, errors.New("plugin instance not found")
	}

	return instance, nil
}

// RegisterHook registers a new hook
func (m *Manager) RegisterHook(hook string) {
	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()

	if _, exists := m.hooks[hook]; !exists {
		m.hooks[hook] = []string{}
		m.logger.Info("Hook registered", map[string]interface{}{
			"hook": hook,
		})
	}
}

// registerPluginHooks registers plugin for its hooks
func (m *Manager) registerPluginHooks(instance *PluginInstance) {
	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()

	for _, hook := range instance.Metadata.Hooks {
		if _, exists := m.hooks[hook]; !exists {
			m.hooks[hook] = []string{}
		}
		m.hooks[hook] = append(m.hooks[hook], instance.ID)
	}
}

// unregisterPluginHooks unregisters plugin from its hooks
func (m *Manager) unregisterPluginHooks(instance *PluginInstance) {
	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()

	for _, hook := range instance.Metadata.Hooks {
		if pluginIDs, exists := m.hooks[hook]; exists {
			for i, id := range pluginIDs {
				if id == instance.ID {
					m.hooks[hook] = append(pluginIDs[:i], pluginIDs[i+1:]...)
					break
				}
			}
		}
	}
}

// GetHookSubscriptions returns plugins subscribed to a hook
func (m *Manager) GetHookSubscriptions(hook string) []string {
	m.hooksMu.RLock()
	defer m.hooksMu.RUnlock()

	if pluginIDs, exists := m.hooks[hook]; exists {
		result := make([]string, len(pluginIDs))
		copy(result, pluginIDs)
		return result
	}

	return []string{}
}

// GetPluginStats returns statistics for a plugin instance
func (m *Manager) GetPluginStats(instanceID string) (*PluginStats, error) {
	m.instancesMu.RLock()
	instance, exists := m.instances[instanceID]
	m.instancesMu.RUnlock()

	if !exists {
		return nil, errors.New("plugin instance not found")
	}

	instance.mu.RLock()
	defer instance.mu.RUnlock()

	runtimeStats := m.runtime.GetPluginStats(instanceID)

	return &PluginStats{
		InstanceID:      instanceID,
		State:           instance.State,
		LoadedAt:        instance.LoadedAt,
		LastExecution:   instance.LastExecution,
		ExecutionCount:  instance.ExecutionCount,
		ErrorCount:      instance.ErrorCount,
		SuccessRate:     float64(instance.ExecutionCount-instance.ErrorCount) / float64(instance.ExecutionCount),
		RuntimeStats:    runtimeStats,
	}, nil
}

// Cleanup shuts down the plugin manager
func (m *Manager) Cleanup(ctx context.Context) error {
	m.instancesMu.Lock()
	defer m.instancesMu.Unlock()

	var errors []error

	// Unload all plugins
	for instanceID, instance := range m.instances {
		err := m.runtime.DisposePlugin(instanceID)
		if err != nil {
			errors = append(errors, err)
			m.logger.Error("Failed to dispose plugin during cleanup", map[string]interface{}{
				"instance_id": instanceID,
				"plugin_id":   instance.PluginID,
				"error":       err.Error(),
			})
		}
	}

	// Clear instances
	m.instances = make(map[string]*PluginInstance)

	// Clear hooks
	m.hooksMu.Lock()
	m.hooks = make(map[string][]string)
	m.hooksMu.Unlock()

	// Cleanup runtime
	err := m.runtime.Cleanup()
	if err != nil {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup completed with %d errors: %v", len(errors), errors)
	}

	m.logger.Info("Plugin manager cleanup completed")
	return nil
}

// Supporting types and interfaces

type PluginStats struct {
	InstanceID     string                 `json:"instance_id"`
	State          PluginState            `json:"state"`
	LoadedAt       time.Time              `json:"loaded_at"`
	LastExecution  time.Time              `json:"last_execution"`
	ExecutionCount int64                  `json:"execution_count"`
	ErrorCount     int64                  `json:"error_count"`
	SuccessRate    float64                `json:"success_rate"`
	RuntimeStats   interface{}            `json:"runtime_stats"`
}

type PluginExecutionMetrics struct {
	Hook          string        `json:"hook"`
	Success       bool          `json:"success"`
	ExecutionTime time.Duration `json:"execution_time"`
	MemoryUsed    int           `json:"memory_used"`
	CPUTime       time.Duration `json:"cpu_time"`
}

type EventBus interface {
	Publish(topic string, payload interface{}) error
	Subscribe(topic string, handler func(payload interface{})) error
}

type MetricsCollector interface {
	RecordPluginExecution(pluginID string, metrics PluginExecutionMetrics)
}