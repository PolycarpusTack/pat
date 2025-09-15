package container

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/config"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// FortressContainer manages all fortress services and their dependencies
type FortressContainer struct {
	// Core fortress services
	keep       interfaces.Keep
	watchtower interfaces.Watchtower
	guard      interfaces.Guard
	rampart    interfaces.Rampart
	armory     interfaces.Armory
	gates      interfaces.Gates
	foundation interfaces.Foundation
	eventBus   interfaces.EventBus

	// Configuration and utilities
	config *config.Config
	logger *zap.Logger

	// Container state management
	mu       sync.RWMutex
	started  bool
	starting bool
	stopping bool
	services map[string]ServiceInfo
	
	// Service lifecycle hooks
	startHooks []StartHook
	stopHooks  []StopHook
	
	// Health monitoring
	healthChecks map[string]interfaces.HealthCheckFunc
	lastHealth   time.Time
}

// ServiceInfo contains metadata about registered services
type ServiceInfo struct {
	Name        string
	Service     interface{}
	Status      ServiceStatus
	StartedAt   *time.Time
	LastHealth  *interfaces.HealthStatus
	Dependencies []string
}

// ServiceStatus represents service status
type ServiceStatus string

const (
	ServiceStatusStopped  ServiceStatus = "stopped"
	ServiceStatusStarting ServiceStatus = "starting"
	ServiceStatusRunning  ServiceStatus = "running"
	ServiceStatusStopping ServiceStatus = "stopping"
	ServiceStatusError    ServiceStatus = "error"
)

// StartHook is called before service startup
type StartHook func(ctx context.Context, container *FortressContainer) error

// StopHook is called before service shutdown
type StopHook func(ctx context.Context, container *FortressContainer) error

// NewFortressContainer creates a new fortress container with configuration
func NewFortressContainer(ctx context.Context, cfg *config.Config) (*FortressContainer, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	container := &FortressContainer{
		config:       cfg,
		logger:       logger,
		services:     make(map[string]ServiceInfo),
		healthChecks: make(map[string]interfaces.HealthCheckFunc),
	}

	// Initialize services based on configuration
	if err := container.initializeServices(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	logger.Info("Fortress container created successfully")
	return container, nil
}

// initializeServices creates and configures all fortress services
func (c *FortressContainer) initializeServices(ctx context.Context) error {
	c.logger.Info("Initializing fortress services")

	// Initialize services in dependency order
	if err := c.initFoundation(ctx); err != nil {
		return fmt.Errorf("failed to initialize foundation: %w", err)
	}

	if err := c.initWatchtower(ctx); err != nil {
		return fmt.Errorf("failed to initialize watchtower: %w", err)
	}

	if err := c.initEventBus(ctx); err != nil {
		return fmt.Errorf("failed to initialize event bus: %w", err)
	}

	if err := c.initGuard(ctx); err != nil {
		return fmt.Errorf("failed to initialize guard: %w", err)
	}

	if err := c.initRampart(ctx); err != nil {
		return fmt.Errorf("failed to initialize rampart: %w", err)
	}

	if err := c.initKeep(ctx); err != nil {
		return fmt.Errorf("failed to initialize keep: %w", err)
	}

	if err := c.initArmory(ctx); err != nil {
		return fmt.Errorf("failed to initialize armory: %w", err)
	}

	if err := c.initGates(ctx); err != nil {
		return fmt.Errorf("failed to initialize gates: %w", err)
	}

	c.logger.Info("All fortress services initialized successfully")
	return nil
}

// Start starts all fortress services in the correct order
func (c *FortressContainer) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started || c.starting {
		return fmt.Errorf("container is already started or starting")
	}

	c.starting = true
	c.logger.Info("Starting fortress container")

	// Execute pre-start hooks
	for _, hook := range c.startHooks {
		if err := hook(ctx, c); err != nil {
			c.starting = false
			return fmt.Errorf("start hook failed: %w", err)
		}
	}

	// Start services in dependency order
	startOrder := []string{
		"foundation", "watchtower", "eventBus", "guard", 
		"rampart", "keep", "armory", "gates",
	}

	for _, serviceName := range startOrder {
		if err := c.startService(ctx, serviceName); err != nil {
			c.starting = false
			// Attempt to stop any services that were started
			c.stopAllServices(ctx)
			return fmt.Errorf("failed to start service %s: %w", serviceName, err)
		}
	}

	c.started = true
	c.starting = false

	// Start background health monitoring
	go c.runHealthMonitoring(ctx)

	c.logger.Info("Fortress container started successfully")
	return nil
}

// Stop stops all fortress services in reverse order
func (c *FortressContainer) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started || c.stopping {
		return fmt.Errorf("container is not started or already stopping")
	}

	c.stopping = true
	c.logger.Info("Stopping fortress container")

	// Execute pre-stop hooks
	for _, hook := range c.stopHooks {
		if err := hook(ctx, c); err != nil {
			c.logger.Error("Stop hook failed", zap.Error(err))
		}
	}

	// Stop all services
	if err := c.stopAllServices(ctx); err != nil {
		c.logger.Error("Error stopping services", zap.Error(err))
	}

	c.started = false
	c.stopping = false

	c.logger.Info("Fortress container stopped")
	return nil
}

// Health returns the overall health status of the fortress
func (c *FortressContainer) Health(ctx context.Context) *interfaces.HealthStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := &interfaces.HealthStatus{
		Service:   "fortress-container",
		Status:    interfaces.HealthStatusHealthy,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if !c.started {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = "Container not started"
		return status
	}

	// Aggregate service health
	serviceStatuses := make(map[string]string)
	unhealthyCount := 0
	degradedCount := 0

	for name, info := range c.services {
		if info.LastHealth != nil {
			serviceStatuses[name] = string(info.LastHealth.Status)
			switch info.LastHealth.Status {
			case interfaces.HealthStatusUnhealthy:
				unhealthyCount++
			case interfaces.HealthStatusDegraded:
				degradedCount++
			}
		} else {
			serviceStatuses[name] = "unknown"
		}
	}

	status.Details["services"] = serviceStatuses
	status.Details["unhealthyCount"] = unhealthyCount
	status.Details["degradedCount"] = degradedCount

	// Determine overall status
	if unhealthyCount > 0 {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = fmt.Sprintf("%d services unhealthy", unhealthyCount)
	} else if degradedCount > 0 {
		status.Status = interfaces.HealthStatusDegraded
		status.Message = fmt.Sprintf("%d services degraded", degradedCount)
	}

	return status
}

// Service accessors
func (c *FortressContainer) Keep() interfaces.Keep             { return c.keep }
func (c *FortressContainer) Watchtower() interfaces.Watchtower { return c.watchtower }
func (c *FortressContainer) Guard() interfaces.Guard           { return c.guard }
func (c *FortressContainer) Rampart() interfaces.Rampart       { return c.rampart }
func (c *FortressContainer) Armory() interfaces.Armory         { return c.armory }
func (c *FortressContainer) Gates() interfaces.Gates           { return c.gates }
func (c *FortressContainer) Foundation() interfaces.Foundation { return c.foundation }
func (c *FortressContainer) EventBus() interfaces.EventBus     { return c.eventBus }
func (c *FortressContainer) Config() *config.Config            { return c.config }
func (c *FortressContainer) Logger() *zap.Logger               { return c.logger }

// AddStartHook adds a hook to be executed before service startup
func (c *FortressContainer) AddStartHook(hook StartHook) {
	c.startHooks = append(c.startHooks, hook)
}

// AddStopHook adds a hook to be executed before service shutdown
func (c *FortressContainer) AddStopHook(hook StopHook) {
	c.stopHooks = append(c.stopHooks, hook)
}

// RegisterHealthCheck registers a custom health check
func (c *FortressContainer) RegisterHealthCheck(name string, check interfaces.HealthCheckFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthChecks[name] = check
}

// IsStarted returns true if the container is started
func (c *FortressContainer) IsStarted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started
}

// GetServiceInfo returns information about a specific service
func (c *FortressContainer) GetServiceInfo(name string) (ServiceInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, exists := c.services[name]
	return info, exists
}

// ListServices returns information about all registered services
func (c *FortressContainer) ListServices() map[string]ServiceInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	result := make(map[string]ServiceInfo)
	for name, info := range c.services {
		result[name] = info
	}
	return result
}

// Private helper methods

func (c *FortressContainer) startService(ctx context.Context, serviceName string) error {
	info, exists := c.services[serviceName]
	if !exists {
		return fmt.Errorf("service %s not found", serviceName)
	}

	info.Status = ServiceStatusStarting
	c.services[serviceName] = info

	c.logger.Info("Starting service", zap.String("service", serviceName))

	var err error
	startTime := time.Now()

	// Start service based on its type
	switch service := info.Service.(type) {
	case interfaces.Foundation:
		err = service.Start(ctx)
	case interfaces.Watchtower:
		err = service.StartMonitoring(ctx)
	case interfaces.EventBus:
		err = service.Start(ctx)
	case interfaces.Guard:
		err = service.Start(ctx)
	case interfaces.Rampart:
		err = service.Start(ctx)
	case interfaces.Keep:
		err = service.Start(ctx)
	case interfaces.Armory:
		err = service.Start(ctx)
	case interfaces.Gates:
		err = service.Start(ctx)
	default:
		err = fmt.Errorf("unknown service type for %s", serviceName)
	}

	if err != nil {
		info.Status = ServiceStatusError
		c.services[serviceName] = info
		return err
	}

	info.Status = ServiceStatusRunning
	info.StartedAt = &startTime
	c.services[serviceName] = info

	c.logger.Info("Service started successfully", 
		zap.String("service", serviceName),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (c *FortressContainer) stopAllServices(ctx context.Context) error {
	// Stop services in reverse dependency order
	stopOrder := []string{
		"gates", "armory", "keep", "rampart", 
		"guard", "eventBus", "watchtower", "foundation",
	}

	var lastError error

	for _, serviceName := range stopOrder {
		if err := c.stopService(ctx, serviceName); err != nil {
			c.logger.Error("Error stopping service", 
				zap.String("service", serviceName), 
				zap.Error(err))
			lastError = err
		}
	}

	return lastError
}

func (c *FortressContainer) stopService(ctx context.Context, serviceName string) error {
	info, exists := c.services[serviceName]
	if !exists {
		return nil // Service doesn't exist, nothing to stop
	}

	if info.Status != ServiceStatusRunning {
		return nil // Service not running, nothing to stop
	}

	info.Status = ServiceStatusStopping
	c.services[serviceName] = info

	c.logger.Info("Stopping service", zap.String("service", serviceName))

	var err error

	// Stop service based on its type
	switch service := info.Service.(type) {
	case interfaces.Foundation:
		err = service.Stop(ctx)
	case interfaces.Watchtower:
		err = service.StopMonitoring(ctx)
	case interfaces.EventBus:
		err = service.Stop(ctx)
	case interfaces.Guard:
		err = service.Stop(ctx)
	case interfaces.Rampart:
		err = service.Stop(ctx)
	case interfaces.Keep:
		err = service.Stop(ctx)
	case interfaces.Armory:
		err = service.Stop(ctx)
	case interfaces.Gates:
		err = service.Stop(ctx)
	}

	info.Status = ServiceStatusStopped
	info.StartedAt = nil
	c.services[serviceName] = info

	if err != nil {
		c.logger.Error("Error stopping service", 
			zap.String("service", serviceName), 
			zap.Error(err))
		return err
	}

	c.logger.Info("Service stopped successfully", zap.String("service", serviceName))
	return nil
}

func (c *FortressContainer) runHealthMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Health check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.performHealthChecks(ctx)
		}
	}
}

func (c *FortressContainer) performHealthChecks(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastHealth = time.Now()

	// Check each service
	for serviceName, info := range c.services {
		if info.Status != ServiceStatusRunning {
			continue
		}

		var health *interfaces.HealthStatus

		// Get health from service
		switch service := info.Service.(type) {
		case interfaces.Foundation:
			health = service.Health(ctx)
		case interfaces.Watchtower:
			health = service.HealthCheck(ctx)
		case interfaces.EventBus:
			health = service.Health(ctx)
		case interfaces.Guard:
			health = service.Health(ctx)
		case interfaces.Rampart:
			health = service.Health(ctx)
		case interfaces.Keep:
			health = service.Health(ctx)
		case interfaces.Armory:
			health = service.Health(ctx)
		case interfaces.Gates:
			health = service.Health(ctx)
		}

		if health != nil {
			info.LastHealth = health
			c.services[serviceName] = info

			// Log unhealthy services
			if health.Status == interfaces.HealthStatusUnhealthy {
				c.logger.Warn("Service unhealthy", 
					zap.String("service", serviceName),
					zap.String("message", health.Message))
			}
		}
	}

	// Run custom health checks
	for checkName, checkFunc := range c.healthChecks {
		if health := checkFunc(ctx); health != nil {
			if health.Status == interfaces.HealthStatusUnhealthy {
				c.logger.Warn("Custom health check failed",
					zap.String("check", checkName),
					zap.String("message", health.Message))
			}
		}
	}
}