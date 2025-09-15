package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pat-fortress/pkg/fortress/config"
	"github.com/pat-fortress/pkg/fortress/container"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// FortressDemo demonstrates the complete fortress service integration
func main() {
	fmt.Println("🏰 FORTRESS ARCHITECTURE DEMONSTRATION")
	fmt.Println("=====================================")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.LoadConfig("") // Uses defaults
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	// Override with demo-specific settings
	configureDemoSettings(cfg)

	// Create fortress container
	ctx := context.Background()
	fortress, err := container.NewFortressContainer(ctx, cfg)
	if err != nil {
		logger.Fatal("Failed to create fortress container", zap.Error(err))
	}

	logger.Info("🏰 Fortress container created successfully")

	// Add custom start hooks
	fortress.AddStartHook(func(ctx context.Context, container *container.FortressContainer) error {
		logger.Info("🚀 Fortress initialization hook executing")
		return setupDemoData(ctx, container)
	})

	// Add custom stop hooks
	fortress.AddStopHook(func(ctx context.Context, container *container.FortressContainer) error {
		logger.Info("🛑 Fortress shutdown hook executing")
		return cleanupDemoData(ctx, container)
	})

	// Register custom health checks
	fortress.RegisterHealthCheck("demo_health", func(ctx context.Context) *interfaces.HealthStatus {
		return &interfaces.HealthStatus{
			Service:   "demo",
			Status:    interfaces.HealthStatusHealthy,
			Message:   "Demo health check passed",
			Timestamp: time.Now(),
		}
	})

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go handleShutdown(cancel, fortress, logger)

	// Start the fortress
	logger.Info("🏰 Starting Fortress...")
	if err := fortress.Start(ctx); err != nil {
		logger.Fatal("Failed to start fortress", zap.Error(err))
	}

	logger.Info("🏰 Fortress is operational!")
	
	// Run demonstration scenarios
	runFortressDemonstration(ctx, fortress, logger)

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("🏰 Fortress shutdown initiated")

	// Stop the fortress
	if err := fortress.Stop(ctx); err != nil {
		logger.Error("Error stopping fortress", zap.Error(err))
	}

	logger.Info("🏰 Fortress demonstration completed")
}

// configureDemoSettings configures fortress for demonstration
func configureDemoSettings(cfg *config.Config) {
	// Use SQLite for simplicity
	cfg.Database.Driver = "sqlite3"
	cfg.Database.DSN = "./fortress_demo.db"

	// Enable all features for demo
	cfg.Security.RateLimiting.Enabled = true
	cfg.Security.Scanning.Enabled = true
	cfg.Email.Analytics.Enabled = true
	cfg.Plugins.EnableSandbox = true
	cfg.Monitoring.MetricsEnabled = true
	cfg.Monitoring.TracingEnabled = true
	cfg.Events.PersistEvents = true

	// Demo-friendly ports
	cfg.Server.HTTPPort = 8025
	cfg.SMTP.Port = 1025
	cfg.Monitoring.MetricsPort = 9090

	fmt.Printf("📋 Demo configuration loaded:\n")
	fmt.Printf("   • HTTP Port: %d\n", cfg.Server.HTTPPort)
	fmt.Printf("   • SMTP Port: %d\n", cfg.SMTP.Port)
	fmt.Printf("   • Database: %s\n", cfg.Database.Driver)
	fmt.Printf("   • Metrics: %t\n", cfg.Monitoring.MetricsEnabled)
	fmt.Printf("   • Security: %t\n", cfg.Security.RateLimiting.Enabled)
}

// setupDemoData initializes demo data
func setupDemoData(ctx context.Context, fortress *container.FortressContainer) error {
	fmt.Println("🔧 Setting up demo data...")

	// Create demo user
	guard := fortress.Guard()
	user := &interfaces.User{
		ID:          "demo-user-001",
		Username:    "demo",
		Email:       "demo@fortress.local",
		DisplayName: "Demo User",
		Roles:       []string{"admin", "user"},
		Permissions: []string{"email:read", "email:write", "admin:all"},
		Active:      true,
	}

	if err := guard.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create demo user: %w", err)
	}

	// Subscribe to events for demonstration
	eventBus := fortress.EventBus()
	
	// Email processing events
	eventBus.Subscribe("email.received", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("📧 Email received: %s\n", event.Data["email_id"])
		return nil
	})

	eventBus.Subscribe("email.processed", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("✅ Email processed: %s\n", event.Data["email_id"])
		return nil
	})

	eventBus.Subscribe("email.stored", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("💾 Email stored: %s (size: %v bytes)\n", 
			event.Data["email_id"], event.Data["size"])
		return nil
	})

	// Security events
	eventBus.Subscribe("security.threat_detected", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("⚠️  Security threat detected: %s\n", event.Data["email_id"])
		return nil
	})

	fmt.Println("✅ Demo data setup completed")
	return nil
}

// cleanupDemoData cleans up demo resources
func cleanupDemoData(ctx context.Context, fortress *container.FortressContainer) error {
	fmt.Println("🧹 Cleaning up demo data...")
	// Implementation would clean up demo resources
	return nil
}

// runFortressDemonstration runs various demonstration scenarios
func runFortressDemonstration(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	// Run demonstrations in a separate goroutine
	go func() {
		time.Sleep(2 * time.Second) // Wait for startup

		logger.Info("🎭 Starting fortress demonstrations")

		// Demo 1: Email Processing Pipeline
		demonstrateEmailProcessing(ctx, fortress, logger)

		// Demo 2: Security and Rate Limiting
		demonstrateSecurityFeatures(ctx, fortress, logger)

		// Demo 3: Monitoring and Observability  
		demonstrateMonitoring(ctx, fortress, logger)

		// Demo 4: Event System
		demonstrateEventSystem(ctx, fortress, logger)

		// Demo 5: Data Access and Transactions
		demonstrateDataAccess(ctx, fortress, logger)

		// Demo 6: Health Checks
		demonstrateHealthChecks(ctx, fortress, logger)

		logger.Info("🎭 All demonstrations completed")
	}()
}

// demonstrateEmailProcessing shows the email processing pipeline
func demonstrateEmailProcessing(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n🔄 DEMONSTRATION: Email Processing Pipeline")
	fmt.Println("==========================================")

	keep := fortress.Keep()
	watchtower := fortress.Watchtower()

	// Create a sample email
	email := &interfaces.Email{
		ID:        "demo-email-001",
		MessageID: "<demo@fortress.local>",
		From:      "sender@example.com",
		To:        []string{"recipient@fortress.local"},
		Subject:   "Demo Email - Fortress Architecture Test",
		Body:      "This is a demonstration email for the Fortress architecture.",
		HTMLBody:  "<p>This is a <strong>demonstration email</strong> for the Fortress architecture.</p>",
		Headers: map[string]string{
			"Date":       time.Now().Format(time.RFC1123Z),
			"From":       "sender@example.com",
			"To":         "recipient@fortress.local",
			"Subject":    "Demo Email - Fortress Architecture Test",
			"Message-ID": "<demo@fortress.local>",
		},
		ReceivedAt: time.Now(),
		Size:       1024,
		Metadata:   make(map[string]interface{}),
	}

	// Start trace for email processing
	ctx, span := watchtower.StartTrace(ctx, "demo_email_processing")
	defer span.End()

	// Process the email through The Keep
	fmt.Printf("📧 Processing email: %s\n", email.Subject)
	
	if err := keep.ProcessEmail(ctx, email); err != nil {
		logger.Error("Email processing failed", zap.Error(err))
		span.SetError(err)
		return
	}

	fmt.Printf("✅ Email processed successfully\n")

	// Retrieve the processed email
	retrievedEmail, err := keep.RetrieveEmail(ctx, email.ID)
	if err != nil {
		logger.Error("Email retrieval failed", zap.Error(err))
		return
	}

	fmt.Printf("📖 Retrieved email: %s (size: %d bytes)\n", 
		retrievedEmail.Subject, retrievedEmail.Size)

	// Search for emails
	searchResults, err := keep.SearchEmails(ctx, &interfaces.SearchQuery{
		Query: "fortress",
		Limit: 10,
	})
	if err != nil {
		logger.Error("Email search failed", zap.Error(err))
		return
	}

	fmt.Printf("🔍 Search results: found %d emails\n", searchResults.Total)

	// Get email statistics
	stats, err := keep.GetEmailStats(ctx, nil)
	if err != nil {
		logger.Error("Failed to get email stats", zap.Error(err))
		return
	}

	fmt.Printf("📊 Email statistics: total=%d, processed=%d\n", 
		stats.Total, stats.Processed)

	fmt.Println("✅ Email processing demonstration completed")
}

// demonstrateSecurityFeatures shows security and rate limiting
func demonstrateSecurityFeatures(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n🛡️  DEMONSTRATION: Security Features")
	fmt.Println("===================================")

	rampart := fortress.Rampart()
	watchtower := fortress.Watchtower()

	// Test rate limiting
	fmt.Printf("🚦 Testing rate limiting...\n")
	
	rateLimit := &interfaces.RateLimit{
		Requests: 5,
		Window:   time.Minute,
		Burst:    2,
	}

	for i := 0; i < 8; i++ {
		result, err := rampart.CheckRateLimit(ctx, "demo-client", rateLimit)
		if err != nil {
			logger.Error("Rate limit check failed", zap.Error(err))
			continue
		}

		if result.Allowed {
			fmt.Printf("   Request %d: ✅ Allowed (remaining: %d)\n", i+1, result.Remaining)
		} else {
			fmt.Printf("   Request %d: ❌ Rate limited (retry after: %v)\n", 
				i+1, result.RetryAfter)
		}

		watchtower.RecordMetric("demo.rate_limit.check", 1, map[string]string{
			"allowed": fmt.Sprintf("%t", result.Allowed),
		})

		time.Sleep(100 * time.Millisecond)
	}

	// Test email scanning
	fmt.Printf("🔍 Testing email security scanning...\n")

	testEmail := &interfaces.Email{
		ID:      "security-test-email",
		From:    "suspicious@malware.com",
		To:      []string{"target@fortress.local"},
		Subject: "URGENT: Click here to win $1000000!",
		Body:    "This email contains suspicious content for testing purposes.",
		Size:    512,
	}

	scanResult, err := rampart.ScanEmail(ctx, testEmail)
	if err != nil {
		logger.Error("Email scan failed", zap.Error(err))
		return
	}

	fmt.Printf("   Security scan result: safe=%t, score=%.2f\n", 
		scanResult.Safe, scanResult.Score)
	
	if len(scanResult.Threats) > 0 {
		fmt.Printf("   Detected threats: %d\n", len(scanResult.Threats))
		for _, threat := range scanResult.Threats {
			fmt.Printf("     - %s: %s (confidence: %.2f)\n", 
				threat.Type, threat.Description, threat.Confidence)
		}
	}

	// Test blacklist checking
	fmt.Printf("🚫 Testing blacklist checking...\n")

	testIPs := []string{"127.0.0.1", "192.168.1.100", "10.0.0.1"}
	for _, ip := range testIPs {
		isBlacklisted, err := rampart.CheckBlacklist(ctx, ip, interfaces.BlacklistTypeIP)
		if err != nil {
			logger.Warn("Blacklist check failed", zap.String("ip", ip), zap.Error(err))
			continue
		}

		status := "✅ Clean"
		if isBlacklisted {
			status = "❌ Blacklisted"
		}
		fmt.Printf("   IP %s: %s\n", ip, status)
	}

	fmt.Println("✅ Security demonstration completed")
}

// demonstrateMonitoring shows monitoring and observability features
func demonstrateMonitoring(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n📊 DEMONSTRATION: Monitoring & Observability")
	fmt.Println("===========================================")

	watchtower := fortress.Watchtower()

	// Record various metrics
	fmt.Printf("📈 Recording metrics...\n")

	metrics := []struct {
		name   string
		value  float64
		labels map[string]string
	}{
		{"demo.emails.processed", 150, map[string]string{"type": "inbox"}},
		{"demo.emails.processed", 75, map[string]string{"type": "spam"}},
		{"demo.response.time", 0.25, map[string]string{"endpoint": "/api/emails"}},
		{"demo.response.time", 0.15, map[string]string{"endpoint": "/api/health"}},
		{"demo.active.connections", 42, nil},
		{"demo.queue.size", 18, map[string]string{"queue": "processing"}},
	}

	for _, metric := range metrics {
		watchtower.RecordMetric(metric.name, metric.value, metric.labels)
		fmt.Printf("   📊 %s = %.2f\n", metric.name, metric.value)
	}

	// Record counters
	fmt.Printf("🔢 Recording counters...\n")
	
	counters := []struct {
		name   string
		labels map[string]string
	}{
		{"demo.requests.total", map[string]string{"method": "GET", "status": "200"}},
		{"demo.requests.total", map[string]string{"method": "POST", "status": "201"}},
		{"demo.errors.total", map[string]string{"type": "validation"}},
		{"demo.cache.hits", nil},
		{"demo.cache.misses", nil},
	}

	for _, counter := range counters {
		watchtower.IncrementCounter(counter.name, counter.labels)
		fmt.Printf("   🔢 %s incremented\n", counter.name)
	}

	// Record histograms  
	fmt.Printf("📊 Recording histograms...\n")
	
	for i := 0; i < 10; i++ {
		responseTime := 0.1 + float64(i)*0.05
		watchtower.RecordHistogram("demo.request.duration", responseTime, 
			map[string]string{"service": "keep"})
	}
	fmt.Printf("   📊 Request duration histogram recorded (10 samples)\n")

	// Set gauges
	fmt.Printf("📏 Setting gauges...\n")
	
	gauges := []struct {
		name   string
		value  float64
		labels map[string]string
	}{
		{"demo.cpu.usage", 65.5, map[string]string{"core": "0"}},
		{"demo.memory.usage", 78.2, nil},
		{"demo.disk.usage", 45.1, map[string]string{"mount": "/data"}},
		{"demo.active.users", 23, nil},
	}

	for _, gauge := range gauges {
		watchtower.SetGauge(gauge.name, gauge.value, gauge.labels)
		fmt.Printf("   📏 %s = %.2f\n", gauge.name, gauge.value)
	}

	// Demonstrate tracing
	fmt.Printf("🔍 Demonstrating distributed tracing...\n")

	ctx, span := watchtower.StartTrace(ctx, "demo_operation")
	span.SetTag("demo.operation", "monitoring")
	span.SetTag("demo.component", "watchtower")

	// Simulate some work
	time.Sleep(50 * time.Millisecond)
	
	watchtower.RecordSpan(span, "success", map[string]interface{}{
		"demo.duration_ms": 50,
		"demo.status":      "completed",
	})
	
	span.End()
	fmt.Printf("   🔍 Trace span completed: %s\n", span.GetTraceID())

	// Log structured events
	fmt.Printf("📝 Logging structured events...\n")

	watchtower.LogEvent(interfaces.LogLevelInfo, "Demo monitoring event", map[string]interface{}{
		"component":    "demo",
		"operation":    "monitoring",
		"metrics_sent": len(metrics),
		"timestamp":    time.Now(),
	})

	// Test system stats
	systemStats, err := watchtower.GetSystemStats(ctx)
	if err != nil {
		logger.Error("Failed to get system stats", zap.Error(err))
		return
	}

	fmt.Printf("💻 System statistics:\n")
	fmt.Printf("   • CPU Usage: %.1f%%\n", systemStats.CPU)
	fmt.Printf("   • Goroutines: %d\n", systemStats.Goroutines)
	fmt.Printf("   • Uptime: %v\n", systemStats.Uptime)

	if systemStats.Memory != nil {
		fmt.Printf("   • Memory Usage: %.1f%%\n", systemStats.Memory.UsagePercent)
	}

	fmt.Println("✅ Monitoring demonstration completed")
}

// demonstrateEventSystem shows event-driven communication
func demonstrateEventSystem(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n🔔 DEMONSTRATION: Event System")
	fmt.Println("=============================")

	eventBus := fortress.EventBus()

	// Subscribe to custom events
	fmt.Printf("📡 Setting up event subscribers...\n")

	// Counter for received events
	eventCount := 0

	// Subscribe to demo events
	eventBus.Subscribe("demo.test", func(ctx context.Context, event *interfaces.Event) error {
		eventCount++
		fmt.Printf("   📨 Received demo.test event #%d: %s\n", 
			eventCount, event.Data["message"])
		return nil
	})

	eventBus.Subscribe("demo.error", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("   ❌ Received demo.error event: %s\n", 
			event.Data["error_message"])
		return nil
	})

	eventBus.Subscribe("demo.workflow", func(ctx context.Context, event *interfaces.Event) error {
		fmt.Printf("   🔄 Workflow event: %s -> %s\n", 
			event.Data["from_state"], event.Data["to_state"])
		return nil
	})

	// Publish test events
	fmt.Printf("📤 Publishing test events...\n")

	// Synchronous event publishing
	events := []*interfaces.Event{
		{
			Type:   "demo.test",
			Source: "demo",
			Data: map[string]interface{}{
				"message": "Hello from synchronous event!",
				"number":  1,
			},
		},
		{
			Type:   "demo.workflow",
			Source: "demo",
			Data: map[string]interface{}{
				"from_state": "initialized",
				"to_state":   "processing",
				"entity_id":  "demo-001",
			},
		},
		{
			Type:   "demo.error",
			Source: "demo",
			Data: map[string]interface{}{
				"error_message": "This is a test error event",
				"severity":      "low",
			},
		},
	}

	for i, event := range events {
		fmt.Printf("   📤 Publishing event %d: %s\n", i+1, event.Type)
		
		if err := eventBus.Publish(ctx, event); err != nil {
			logger.Error("Failed to publish event", zap.Error(err))
		}
		
		time.Sleep(100 * time.Millisecond)
	}

	// Asynchronous event publishing
	fmt.Printf("📤 Publishing async events...\n")

	asyncEvents := []*interfaces.Event{
		{
			Type:   "demo.test",
			Source: "demo",
			Data: map[string]interface{}{
				"message": "Hello from async event!",
				"number":  2,
			},
		},
		{
			Type:   "demo.workflow", 
			Source: "demo",
			Data: map[string]interface{}{
				"from_state": "processing",
				"to_state":   "completed",
				"entity_id":  "demo-001",
			},
		},
	}

	for i, event := range asyncEvents {
		fmt.Printf("   📤 Publishing async event %d: %s\n", i+1, event.Type)
		
		if err := eventBus.PublishAsync(ctx, event); err != nil {
			logger.Error("Failed to publish async event", zap.Error(err))
		}
	}

	// Wait for async events to process
	time.Sleep(500 * time.Millisecond)

	// List subscriptions
	subscriptions, err := eventBus.ListSubscriptions(ctx)
	if err != nil {
		logger.Error("Failed to list subscriptions", zap.Error(err))
		return
	}

	fmt.Printf("📋 Active subscriptions (%d):\n", len(subscriptions))
	for _, eventType := range subscriptions {
		fmt.Printf("   • %s\n", eventType)
	}

	fmt.Printf("📊 Total events processed: %d\n", eventCount)
	
	fmt.Println("✅ Event system demonstration completed")
}

// demonstrateDataAccess shows database and storage operations
func demonstrateDataAccess(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n💾 DEMONSTRATION: Data Access & Storage")
	fmt.Println("======================================")

	foundation := fortress.Foundation()

	// Test basic queries
	fmt.Printf("🔍 Testing database queries...\n")

	// Simple query test
	result, err := foundation.QueryOne(ctx, "SELECT 1 as test_value, 'hello' as test_string")
	if err != nil {
		logger.Error("Query test failed", zap.Error(err))
		return
	}

	fmt.Printf("   Query result: %+v\n", result)

	// Test transactions
	fmt.Printf("🔄 Testing database transactions...\n")

	err = foundation.Transaction(ctx, func(tx interfaces.Transaction) error {
		fmt.Printf("   📝 Executing transaction operations...\n")
		
		// This would be actual SQL operations
		fmt.Printf("   • Creating demo table\n")
		fmt.Printf("   • Inserting demo records\n")
		fmt.Printf("   • Updating demo records\n")
		
		// Simulate some work
		time.Sleep(100 * time.Millisecond)
		
		return nil // Success - transaction will commit
	})

	if err != nil {
		logger.Error("Transaction failed", zap.Error(err))
		return
	}

	fmt.Printf("   ✅ Transaction completed successfully\n")

	// Test cache operations
	fmt.Printf("💨 Testing cache operations...\n")

	cacheTests := []struct {
		key   string
		value interface{}
		ttl   *time.Duration
	}{
		{"demo:user:123", map[string]string{"name": "Demo User", "email": "demo@fortress.local"}, nil},
		{"demo:config", "cache_value_123", &[]time.Duration{5 * time.Minute}[0]},
		{"demo:counter", 42, nil},
	}

	for _, test := range cacheTests {
		// Set cache value
		if err := foundation.CacheSet(ctx, test.key, test.value, test.ttl); err != nil {
			logger.Error("Cache set failed", zap.String("key", test.key), zap.Error(err))
			continue
		}

		// Get cache value
		value, err := foundation.CacheGet(ctx, test.key)
		if err != nil {
			logger.Error("Cache get failed", zap.String("key", test.key), zap.Error(err))
			continue
		}

		fmt.Printf("   💨 %s: %v\n", test.key, value)
	}

	// Test file storage
	fmt.Printf("📁 Testing file storage...\n")

	fileTests := []struct {
		path string
		data string
	}{
		{"demo/test1.txt", "Hello Fortress!"},
		{"demo/config.json", `{"fortress": {"demo": true}}`},
		{"logs/demo.log", "Demo log entry: " + time.Now().String()},
	}

	for _, test := range fileTests {
		// Store file
		if err := foundation.StoreFile(ctx, test.path, []byte(test.data)); err != nil {
			logger.Error("File store failed", zap.String("path", test.path), zap.Error(err))
			continue
		}

		// Retrieve file
		data, err := foundation.RetrieveFile(ctx, test.path)
		if err != nil {
			logger.Error("File retrieve failed", zap.String("path", test.path), zap.Error(err))
			continue
		}

		fmt.Printf("   📁 %s: %s\n", test.path, string(data))
	}

	// List files
	files, err := foundation.ListFiles(ctx, "demo/*")
	if err != nil {
		logger.Error("File listing failed", zap.Error(err))
		return
	}

	fmt.Printf("📋 Files in demo/ directory (%d):\n", len(files))
	for _, file := range files {
		fmt.Printf("   • %s\n", file)
	}

	// Test backup operations
	fmt.Printf("💿 Testing backup operations...\n")

	backupConfig := &interfaces.BackupConfig{
		Type:        "demo",
		Destination: "/backups/demo_backup.sql",
		Schedule:    "0 2 * * *", // Daily at 2 AM
		Retention:   7 * 24 * time.Hour,
		Compression: true,
		Encryption:  false,
		Options: map[string]string{
			"demo": "true",
		},
	}

	if err := foundation.CreateBackup(ctx, backupConfig); err != nil {
		logger.Error("Backup creation failed", zap.Error(err))
		return
	}

	backups, err := foundation.ListBackups(ctx)
	if err != nil {
		logger.Error("Backup listing failed", zap.Error(err))
		return
	}

	fmt.Printf("💿 Available backups (%d):\n", len(backups))
	for _, backup := range backups {
		fmt.Printf("   • %s: %s (%d bytes) - %s\n", 
			backup.ID, backup.Type, backup.Size, backup.CreatedAt.Format("2006-01-02 15:04"))
	}

	fmt.Println("✅ Data access demonstration completed")
}

// demonstrateHealthChecks shows health monitoring
func demonstrateHealthChecks(ctx context.Context, fortress *container.FortressContainer, logger *zap.Logger) {
	fmt.Println("\n🏥 DEMONSTRATION: Health Checks")
	fmt.Println("==============================")

	// Check overall fortress health
	overallHealth := fortress.Health(ctx)
	fmt.Printf("🏰 Overall Fortress Health: %s\n", overallHealth.Status)
	fmt.Printf("   Message: %s\n", overallHealth.Message)
	
	if overallHealth.Details != nil {
		fmt.Printf("   Details: %+v\n", overallHealth.Details)
	}

	// Check individual service health
	services := map[string]func(context.Context) *interfaces.HealthStatus{
		"Foundation": fortress.Foundation().Health,
		"Watchtower": fortress.Watchtower().HealthCheck,
		"EventBus":   fortress.EventBus().Health,
		"Keep":       fortress.Keep().Health,
		"Guard":      fortress.Guard().Health,
		"Rampart":    fortress.Rampart().Health,
	}

	fmt.Printf("🏥 Individual Service Health:\n")
	for serviceName, healthFunc := range services {
		health := healthFunc(ctx)
		statusIcon := "✅"
		
		switch health.Status {
		case interfaces.HealthStatusDegraded:
			statusIcon = "⚠️"
		case interfaces.HealthStatusUnhealthy:
			statusIcon = "❌"
		case interfaces.HealthStatusUnknown:
			statusIcon = "❓"
		}

		fmt.Printf("   %s %s: %s", statusIcon, serviceName, health.Status)
		if health.Message != "" {
			fmt.Printf(" - %s", health.Message)
		}
		fmt.Printf("\n")

		if health.Details != nil && len(health.Details) > 0 {
			for key, value := range health.Details {
				fmt.Printf("      • %s: %v\n", key, value)
			}
		}
	}

	// Service statistics
	serviceInfo := fortress.ListServices()
	fmt.Printf("📊 Service Statistics:\n")
	
	runningCount := 0
	for serviceName, info := range serviceInfo {
		if info.Status == container.ServiceStatusRunning {
			runningCount++
		}

		fmt.Printf("   • %s: %s", serviceName, info.Status)
		if info.StartedAt != nil {
			uptime := time.Since(*info.StartedAt)
			fmt.Printf(" (uptime: %v)", uptime.Truncate(time.Second))
		}
		fmt.Printf("\n")
	}

	fmt.Printf("📈 Summary: %d/%d services running\n", runningCount, len(serviceInfo))

	fmt.Println("✅ Health check demonstration completed")
}

// handleShutdown sets up graceful shutdown handling
func handleShutdown(cancel context.CancelFunc, fortress *container.FortressContainer, logger *zap.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info("Shutdown signal received", zap.String("signal", sig.String()))
	
	fmt.Printf("\n🛑 Shutdown signal received: %s\n", sig.String())
	fmt.Println("🏰 Initiating graceful fortress shutdown...")
	
	cancel()
}