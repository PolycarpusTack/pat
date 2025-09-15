package container

import (
	"context"
	"fmt"
	"time"

	"github.com/pat-fortress/pkg/foundation"
	"github.com/pat-fortress/pkg/watchtower"
	"github.com/pat-fortress/pkg/events"
	"github.com/pat-fortress/pkg/auth"
	"github.com/pat-fortress/pkg/security"
	"github.com/pat-fortress/pkg/keep"
	"github.com/pat-fortress/pkg/armory"
	"github.com/pat-fortress/pkg/gates"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// Service initialization methods

func (c *FortressContainer) initFoundation(ctx context.Context) error {
	c.logger.Info("Initializing Foundation service")

	// Create foundation service with configuration
	foundationConfig := &interfaces.DatabaseConfig{
		Driver:      c.config.Database.Driver,
		DSN:         c.config.Database.DSN,
		MaxConns:    c.config.Database.MaxConnections,
		MaxIdleConns: c.config.Database.MaxIdleConnections,
		MaxLifetime: time.Duration(c.config.Database.MaxLifetimeMinutes) * time.Minute,
		Migrations:  c.config.Database.MigrationsPath,
		Options:     c.config.Database.Options,
	}

	foundationService, err := foundation.NewFoundationService(ctx, foundationConfig, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create foundation service: %w", err)
	}

	c.foundation = foundationService
	c.services["foundation"] = ServiceInfo{
		Name:         "foundation",
		Service:      foundationService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{},
	}

	c.logger.Info("Foundation service initialized")
	return nil
}

func (c *FortressContainer) initWatchtower(ctx context.Context) error {
	c.logger.Info("Initializing Watchtower service")

	// Create watchtower configuration
	watchtowerConfig := &watchtower.Config{
		MetricsEnabled:    c.config.Monitoring.MetricsEnabled,
		TracingEnabled:    c.config.Monitoring.TracingEnabled,
		LogLevel:          c.config.Monitoring.LogLevel,
		MetricsPort:       c.config.Monitoring.MetricsPort,
		AlertingEnabled:   c.config.Monitoring.AlertingEnabled,
		HealthCheckInterval: time.Duration(c.config.Monitoring.HealthCheckIntervalSeconds) * time.Second,
		RetentionDays:     c.config.Monitoring.RetentionDays,
		ExternalEndpoints: c.config.Monitoring.ExternalEndpoints,
	}

	watchtowerService, err := watchtower.NewWatchtowerService(ctx, watchtowerConfig, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create watchtower service: %w", err)
	}

	c.watchtower = watchtowerService
	c.services["watchtower"] = ServiceInfo{
		Name:         "watchtower",
		Service:      watchtowerService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation"},
	}

	c.logger.Info("Watchtower service initialized")
	return nil
}

func (c *FortressContainer) initEventBus(ctx context.Context) error {
	c.logger.Info("Initializing EventBus service")

	// Create event bus configuration
	eventConfig := &events.Config{
		Driver:           c.config.Events.Driver,
		BufferSize:       c.config.Events.BufferSize,
		WorkerCount:      c.config.Events.WorkerCount,
		MaxRetries:       c.config.Events.MaxRetries,
		RetryDelay:       time.Duration(c.config.Events.RetryDelaySeconds) * time.Second,
		PersistEvents:    c.config.Events.PersistEvents,
		EventRetentionDays: c.config.Events.RetentionDays,
		ExternalBrokers:  c.config.Events.ExternalBrokers,
	}

	eventBusService, err := events.NewEventBusService(ctx, eventConfig, c.foundation, c.watchtower, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create event bus service: %w", err)
	}

	c.eventBus = eventBusService
	c.services["eventBus"] = ServiceInfo{
		Name:         "eventBus",
		Service:      eventBusService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation", "watchtower"},
	}

	c.logger.Info("EventBus service initialized")
	return nil
}

func (c *FortressContainer) initGuard(ctx context.Context) error {
	c.logger.Info("Initializing Guard service")

	// Create guard configuration
	guardConfig := &auth.GuardConfig{
		JWTSecret:           c.config.Security.JWTSecret,
		TokenExpiry:         time.Duration(c.config.Security.TokenExpiryMinutes) * time.Minute,
		RefreshTokenExpiry:  time.Duration(c.config.Security.RefreshTokenExpiryDays) * 24 * time.Hour,
		PasswordMinLength:   c.config.Security.PasswordMinLength,
		RequireTwoFactor:    c.config.Security.RequireTwoFactor,
		SessionTimeout:      time.Duration(c.config.Security.SessionTimeoutMinutes) * time.Minute,
		MaxFailedAttempts:   c.config.Security.MaxFailedAttempts,
		LockoutDuration:     time.Duration(c.config.Security.LockoutDurationMinutes) * time.Minute,
		EnableAPIKeys:       c.config.Security.EnableAPIKeys,
		EnableOAuth:         c.config.Security.EnableOAuth,
		OAuthProviders:      c.config.Security.OAuthProviders,
		PermissionCaching:   c.config.Security.PermissionCaching,
	}

	guardService, err := auth.NewGuardService(ctx, guardConfig, c.foundation, c.eventBus, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create guard service: %w", err)
	}

	c.guard = guardService
	c.services["guard"] = ServiceInfo{
		Name:         "guard",
		Service:      guardService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation", "eventBus"},
	}

	c.logger.Info("Guard service initialized")
	return nil
}

func (c *FortressContainer) initRampart(ctx context.Context) error {
	c.logger.Info("Initializing Rampart service")

	// Create rampart configuration
	rampartConfig := &security.RampartConfig{
		RateLimiting: security.RateLimitConfig{
			Enabled:          c.config.Security.RateLimiting.Enabled,
			DefaultLimit:     c.config.Security.RateLimiting.DefaultRequestsPerMinute,
			WindowSize:       time.Duration(c.config.Security.RateLimiting.WindowSizeMinutes) * time.Minute,
			BurstMultiplier:  c.config.Security.RateLimiting.BurstMultiplier,
			Storage:          c.config.Security.RateLimiting.Storage,
			CustomLimits:     c.config.Security.RateLimiting.CustomLimits,
		},
		SecurityScanning: security.ScanConfig{
			Enabled:             c.config.Security.Scanning.Enabled,
			VirusScanningEnabled: c.config.Security.Scanning.VirusScanningEnabled,
			SpamFilterEnabled:   c.config.Security.Scanning.SpamFilterEnabled,
			PhishingDetection:   c.config.Security.Scanning.PhishingDetection,
			AttachmentScan:      c.config.Security.Scanning.AttachmentScan,
			MaxEmailSize:        c.config.Security.Scanning.MaxEmailSizeBytes,
			QuarantineEnabled:   c.config.Security.Scanning.QuarantineEnabled,
			ThreatSources:       c.config.Security.Scanning.ThreatSources,
		},
		Blacklists: security.BlacklistConfig{
			IPBlacklist:      c.config.Security.Blacklists.IPAddresses,
			EmailBlacklist:   c.config.Security.Blacklists.EmailAddresses,
			DomainBlacklist:  c.config.Security.Blacklists.Domains,
			KeywordBlacklist: c.config.Security.Blacklists.Keywords,
			AutoUpdate:       c.config.Security.Blacklists.AutoUpdate,
			UpdateInterval:   time.Duration(c.config.Security.Blacklists.UpdateIntervalHours) * time.Hour,
		},
		ComplianceMode:   c.config.Security.ComplianceMode,
		DataRetention:    time.Duration(c.config.Security.DataRetentionDays) * 24 * time.Hour,
		AuditLogging:     c.config.Security.AuditLogging,
		AlertingEnabled:  c.config.Security.AlertingEnabled,
	}

	rampartService, err := security.NewRampartService(ctx, rampartConfig, c.foundation, c.eventBus, c.watchtower, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create rampart service: %w", err)
	}

	c.rampart = rampartService
	c.services["rampart"] = ServiceInfo{
		Name:         "rampart",
		Service:      rampartService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation", "eventBus", "watchtower"},
	}

	c.logger.Info("Rampart service initialized")
	return nil
}

func (c *FortressContainer) initKeep(ctx context.Context) error {
	c.logger.Info("Initializing Keep service")

	// Create keep configuration
	keepConfig := &keep.Config{
		EmailProcessing: keep.ProcessingConfig{
			AsyncProcessing:     c.config.Email.AsyncProcessing,
			MaxConcurrentEmails: c.config.Email.MaxConcurrentProcessing,
			ProcessingTimeout:   time.Duration(c.config.Email.ProcessingTimeoutSeconds) * time.Second,
			RetryAttempts:       c.config.Email.RetryAttempts,
			RetryDelay:          time.Duration(c.config.Email.RetryDelaySeconds) * time.Second,
		},
		Storage: keep.StorageConfig{
			CompressEmails:      c.config.Email.Storage.CompressEmails,
			EncryptEmails:       c.config.Email.Storage.EncryptEmails,
			MaxEmailSize:        c.config.Email.Storage.MaxEmailSizeBytes,
			AttachmentStorage:   c.config.Email.Storage.AttachmentStorage,
			IndexEmails:         c.config.Email.Storage.IndexEmails,
			RetentionDays:       c.config.Email.Storage.RetentionDays,
		},
		Search: keep.SearchConfig{
			Enabled:             c.config.Email.Search.Enabled,
			IndexingEnabled:     c.config.Email.Search.IndexingEnabled,
			FullTextSearch:      c.config.Email.Search.FullTextSearch,
			FuzzySearch:         c.config.Email.Search.FuzzySearch,
			SearchTimeout:       time.Duration(c.config.Email.Search.SearchTimeoutSeconds) * time.Second,
			MaxSearchResults:    c.config.Email.Search.MaxResults,
		},
		Analytics: keep.AnalyticsConfig{
			Enabled:            c.config.Email.Analytics.Enabled,
			RealTimeStats:      c.config.Email.Analytics.RealTimeStats,
			HistoricalStats:    c.config.Email.Analytics.HistoricalStats,
			StatisticsRetentionDays: c.config.Email.Analytics.RetentionDays,
		},
		Validation: keep.ValidationConfig{
			ValidateHeaders:    c.config.Email.Validation.ValidateHeaders,
			ValidateStructure:  c.config.Email.Validation.ValidateStructure,
			ValidateEncoding:   c.config.Email.Validation.ValidateEncoding,
			RejectInvalid:      c.config.Email.Validation.RejectInvalid,
		},
	}

	keepService, err := keep.NewKeepService(ctx, keepConfig, c.foundation, c.eventBus, c.watchtower, c.rampart, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create keep service: %w", err)
	}

	c.keep = keepService
	c.services["keep"] = ServiceInfo{
		Name:         "keep",
		Service:      keepService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation", "eventBus", "watchtower", "rampart"},
	}

	c.logger.Info("Keep service initialized")
	return nil
}

func (c *FortressContainer) initArmory(ctx context.Context) error {
	c.logger.Info("Initializing Armory service")

	// Create armory configuration
	armoryConfig := &armory.Config{
		PluginDirectory:      c.config.Plugins.Directory,
		MaxConcurrentPlugins: c.config.Plugins.MaxConcurrentExecutions,
		DefaultTimeout:       time.Duration(c.config.Plugins.DefaultTimeoutSeconds) * time.Second,
		MaxTimeout:           time.Duration(c.config.Plugins.MaxTimeoutSeconds) * time.Second,
		PluginSandbox:        c.config.Plugins.EnableSandbox,
		AllowedPluginTypes:   c.config.Plugins.AllowedTypes,
		SecurityChecks:       c.config.Plugins.SecurityChecks,
		AutoReload:           c.config.Plugins.AutoReload,
		ReloadInterval:       time.Duration(c.config.Plugins.ReloadIntervalMinutes) * time.Minute,
		PluginCaching:        c.config.Plugins.EnableCaching,
		ExecutionLogging:     c.config.Plugins.ExecutionLogging,
		PerformanceMonitoring: c.config.Plugins.PerformanceMonitoring,
		ResourceLimits: armory.ResourceLimits{
			MaxMemoryMB:    c.config.Plugins.ResourceLimits.MaxMemoryMB,
			MaxCPUPercent:  c.config.Plugins.ResourceLimits.MaxCPUPercent,
			MaxExecutionTime: time.Duration(c.config.Plugins.ResourceLimits.MaxExecutionTimeSeconds) * time.Second,
		},
	}

	armoryService, err := armory.NewArmoryService(ctx, armoryConfig, c.foundation, c.eventBus, c.watchtower, c.rampart, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create armory service: %w", err)
	}

	c.armory = armoryService
	c.services["armory"] = ServiceInfo{
		Name:         "armory",
		Service:      armoryService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"foundation", "eventBus", "watchtower", "rampart"},
	}

	c.logger.Info("Armory service initialized")
	return nil
}

func (c *FortressContainer) initGates(ctx context.Context) error {
	c.logger.Info("Initializing Gates service")

	// Create gates configuration
	gatesConfig := &gates.Config{
		HTTP: interfaces.HTTPServerConfig{
			Port:        c.config.Server.HTTPPort,
			Host:        c.config.Server.Host,
			Timeout:     time.Duration(c.config.Server.TimeoutSeconds) * time.Second,
			MaxBodySize: int64(c.config.Server.MaxBodySizeBytes),
			TLS: &interfaces.TLSConfig{
				Enabled:    c.config.Server.TLS.Enabled,
				CertFile:   c.config.Server.TLS.CertFile,
				KeyFile:    c.config.Server.TLS.KeyFile,
				MinVersion: c.config.Server.TLS.MinVersion,
			},
			CORS: &interfaces.CORSConfig{
				AllowedOrigins:   c.config.Server.CORS.AllowedOrigins,
				AllowedMethods:   c.config.Server.CORS.AllowedMethods,
				AllowedHeaders:   c.config.Server.CORS.AllowedHeaders,
				ExposedHeaders:   c.config.Server.CORS.ExposedHeaders,
				AllowCredentials: c.config.Server.CORS.AllowCredentials,
				MaxAge:           c.config.Server.CORS.MaxAge,
			},
		},
		SMTP: interfaces.SMTPServerConfig{
			Port:          c.config.SMTP.Port,
			Host:          c.config.SMTP.Host,
			MaxMsgSize:    int64(c.config.SMTP.MaxMessageSizeBytes),
			MaxRecipients: c.config.SMTP.MaxRecipients,
			Timeout:       time.Duration(c.config.SMTP.TimeoutSeconds) * time.Second,
			TLS: &interfaces.TLSConfig{
				Enabled:    c.config.SMTP.TLS.Enabled,
				CertFile:   c.config.SMTP.TLS.CertFile,
				KeyFile:    c.config.SMTP.TLS.KeyFile,
				MinVersion: c.config.SMTP.TLS.MinVersion,
			},
			Auth: &interfaces.SMTPAuthConfig{
				Enabled:    c.config.SMTP.Auth.Enabled,
				Mechanisms: c.config.SMTP.Auth.Mechanisms,
				Users:      c.config.SMTP.Auth.Users,
			},
		},
		WebSocket: gates.WebSocketConfig{
			Enabled:         c.config.WebSocket.Enabled,
			MaxConnections:  c.config.WebSocket.MaxConnections,
			MessageSizeLimit: c.config.WebSocket.MessageSizeLimitBytes,
			PingInterval:    time.Duration(c.config.WebSocket.PingIntervalSeconds) * time.Second,
			PongTimeout:     time.Duration(c.config.WebSocket.PongTimeoutSeconds) * time.Second,
		},
		GraphQL: gates.GraphQLConfig{
			Enabled:         c.config.GraphQL.Enabled,
			PlaygroundEnabled: c.config.GraphQL.PlaygroundEnabled,
			IntrospectionEnabled: c.config.GraphQL.IntrospectionEnabled,
			MaxComplexity:   c.config.GraphQL.MaxComplexity,
			MaxDepth:        c.config.GraphQL.MaxDepth,
		},
		APIVersioning: gates.APIVersioningConfig{
			DefaultVersion:    c.config.API.DefaultVersion,
			SupportedVersions: c.config.API.SupportedVersions,
			DeprecationNotice: c.config.API.DeprecationNotice,
		},
	}

	gatesService, err := gates.NewGatesService(ctx, gatesConfig, c.keep, c.guard, c.rampart, c.armory, c.eventBus, c.watchtower, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create gates service: %w", err)
	}

	c.gates = gatesService
	c.services["gates"] = ServiceInfo{
		Name:         "gates",
		Service:      gatesService,
		Status:       ServiceStatusStopped,
		Dependencies: []string{"keep", "guard", "rampart", "armory", "eventBus", "watchtower"},
	}

	c.logger.Info("Gates service initialized")
	return nil
}