package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pat-fortress/config"
	"github.com/pat-fortress/pkg/fortress/legacy"
	"github.com/pat-fortress/pkg/fortress/logging"
	"github.com/pat-fortress/pkg/fortress/smtp"
	"github.com/pat-fortress/pkg/fortress/storage"
	fortresshttp "github.com/pat-fortress/pkg/fortress/http"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var (
	version = "fortress-2.0.0"
	logger  *zap.Logger
	store   legacy.FortressMessageStore
	cfg     *config.FortressConfig
)

// initLogger initializes the fortress logger with production-ready configuration
func initLogger() error {
	// Create logging configuration based on environment and flags
	logConfig := &logging.LoggerConfig{
		Level:           logging.LogLevel(cfg.LogLevel),
		Format:          logging.FormatJSON,
		OutputPath:      "stdout",
		ErrorOutputPath: "stderr",
		EnableCaller:    true,
		EnableStacktrace: true,
		SamplingEnabled: true,
		SamplingRate:    100,
		ServiceName:     "pat-fortress",
		ServiceVersion:  version,
		Environment:     getEnvironment(),
		NodeID:         getNodeID(),
	}

	// Override format for development
	if cfg.LogLevel == "debug" {
		logConfig.Format = logging.FormatConsole
		logConfig.SamplingEnabled = false
	}

	var err error
	logger, err = logging.NewLogger(logConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	logger.Info("Logger initialized",
		zap.String("level", string(logConfig.Level)),
		zap.String("format", string(logConfig.Format)),
		zap.String("environment", logConfig.Environment),
		zap.String("service", logConfig.ServiceName),
		zap.String("version", logConfig.ServiceVersion),
	)

	return nil
}

// getEnvironment determines the current environment
func getEnvironment() string {
	if env := os.Getenv("FORTRESS_ENV"); env != "" {
		return env
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if cfg.LogLevel == "debug" {
		return "development"
	}
	return "production"
}

// getNodeID generates a unique node identifier
func getNodeID() string {
	if nodeID := os.Getenv("NODE_ID"); nodeID != "" {
		return nodeID
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

// initStorage initializes the fortress message store
func initStorage() error {
	storageConfig := &storage.StorageConfig{
		Type:         cfg.StorageType,
		DSN:          getStorageDSN(),
		MaxOpenConns: 25,
		MaxIdleConns: 5,
		MaxLifetime:  5 * time.Minute,
		TablePrefix:  "fortress",
		Database:     "fortress",
		RetentionDays: cfg.RetentionDays,
		EnableFullText: true,
	}

	backend, err := storage.NewStorageBackend(storageConfig)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}

	store = backend

	logger.Info("Initialized storage backend",
		zap.String("type", cfg.StorageType),
		zap.Int("retention_days", cfg.RetentionDays))

	return nil
}

// validateConfig performs basic configuration validation
func validateConfig(cfg *config.FortressConfig) error {
	// Validate basic constraints
	if cfg.MaxMessageSize < 1024 {
		return fmt.Errorf("max message size too small: %d bytes (minimum 1KB)", cfg.MaxMessageSize)
	}
	if cfg.MaxMessageSize > 100*1024*1024 {
		return fmt.Errorf("max message size too large: %d bytes (maximum 100MB)", cfg.MaxMessageSize)
	}

	// Validate TLS configuration
	if cfg.EnableTLS {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but cert/key files not specified")
		}
	}

	// Validate rate limiting
	if cfg.EnableRateLimit && cfg.MaxPerIP < 1 {
		return fmt.Errorf("rate limiting enabled but MaxPerIP is %d (must be > 0)", cfg.MaxPerIP)
	}

	// Validate retention
	if cfg.RetentionDays < 0 {
		return fmt.Errorf("retention days cannot be negative: %d", cfg.RetentionDays)
	}

	return nil
}

// getStorageDSN constructs the database connection string based on storage type
func getStorageDSN() string {
	// For email testing, memory storage is sufficient
	// Keep it simple - no complex database setup needed
	return ""
}

func main() {
	// Handle version flag
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Printf("Pat Fortress version: %s\n", version)
		os.Exit(0)
	}

	// Handle legacy bcrypt utility
	if len(os.Args) > 1 && os.Args[1] == "bcrypt" {
		var pw string
		if len(os.Args) > 2 {
			pw = os.Args[2]
		} else {
			fmt.Print("Enter password: ")
			fmt.Scanln(&pw)
		}
		b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("error bcrypting password: %s", err)
		}
		fmt.Println(string(b))
		os.Exit(0)
	}

	// Register configuration flags and parse
	config.RegisterFlags()
	flag.Parse()

	// Load configuration from environment and flags
	cfg = config.Configure()

	// Simple configuration validation
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Initialize fortress components
	if err := initLogger(); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	if err := initStorage(); err != nil {
		logger.Fatal("Failed to initialize storage", zap.Error(err))
	}

	logger.Info("Starting Pat Fortress",
		zap.String("version", version),
		zap.String("smtp_addr", cfg.SMTPBindAddr),
		zap.String("http_addr", cfg.HTTPBindAddr),
		zap.String("hostname", cfg.Hostname),
		zap.String("storage", cfg.StorageType),
	)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create fortress servers using consolidated configuration
	smtpConfig := &smtp.FortressSMTPConfig{
		BindAddr:         cfg.SMTPBindAddr,
		Hostname:         cfg.Hostname,
		MaxMessageSize:   cfg.MaxMessageSize,
		ReadTimeout:      cfg.ReadTimeout,
		WriteTimeout:     cfg.WriteTimeout,
		MaxConnections:   100,
		EnableTLS:        cfg.EnableTLS,
		TLSCertFile:      cfg.TLSCertFile,
		TLSKeyFile:       cfg.TLSKeyFile,
		EnableSTARTTLS:   true,
		RequireTLS:       false,
		EnableAuth:       cfg.EnableAuth,
		EnableRateLimit:  cfg.EnableRateLimit,
		MaxPerIP:         cfg.MaxPerIP,
		EnableBlacklist:  false,
		EnableAuditLog:   true,
		TenantID:         cfg.TenantID,
	}

	httpConfig := &fortresshttp.FortressHTTPConfig{
		BindAddr:        cfg.HTTPBindAddr,
		WebPath:         cfg.WebPath,
		CORSOrigin:      cfg.CORSOrigin,
		EnableCORS:      true,
		EnableTLS:       cfg.EnableTLS,
		TLSCertFile:     cfg.TLSCertFile,
		TLSKeyFile:      cfg.TLSKeyFile,
		EnableAuth:      cfg.EnableAuth,
		APIKeyRequired:  false,
		EnableRateLimit: cfg.EnableRateLimit,
		MaxPerIP:        cfg.MaxPerIP,
		TenantID:        cfg.TenantID,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		EnableAIAnalysis: cfg.EnableAIAnalysis,
		OpenAIAPIKey:     cfg.OpenAIAPIKey,
		OpenAIModel:      cfg.OpenAIModel,
	}

    // Create servers
    smtpServer := smtp.NewFortressSMTPServer(smtpConfig, store, logger)
    httpServer := fortresshttp.NewFortressHTTPServer(httpConfig, store, logger)

    // Wire SMTP -> WebSocket event notifications
    smtpServer.SetOnMessageCallback(func(msg *legacy.Message) {
        payload := map[string]interface{}{
            "id":        string(msg.ID),
            "from":      func() string { if msg.From != nil { return msg.From.Address }; return "" }(),
            "to":        func() []string { var out []string; for _, a := range msg.To { out = append(out, a.Address) }; return out }(),
            "created":   msg.Created,
            "size":      msg.Content.Size,
            "tenant_id": msg.TenantID,
        }
        httpServer.PublishEvent("message_received", payload)
    })

	// Start servers
	go func() {
		if err := smtpServer.Listen(); err != nil {
			logger.Error("SMTP server error", zap.Error(err))
			cancel()
		}
	}()

	go func() {
		if err := httpServer.Listen(); err != nil {
			logger.Error("HTTP server error", zap.Error(err))
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		logger.Info("Received shutdown signal")
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	// Graceful shutdown
	logger.Info("Shutting down servers...")

	// Shutdown SMTP server
	if err := smtpServer.Shutdown(); err != nil {
		logger.Error("Error shutting down SMTP server", zap.Error(err))
	} else {
		logger.Info("SMTP server shut down successfully")
	}

	// Shutdown HTTP server
	if err := httpServer.Shutdown(); err != nil {
		logger.Error("Error shutting down HTTP server", zap.Error(err))
	} else {
		logger.Info("HTTP server shut down successfully")
	}

	// Close storage
	if closer, ok := store.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			logger.Warn("Error closing storage", zap.Error(err))
		}
	}

	logger.Info("Pat Fortress shut down gracefully")
}

/*

Add some random content to the end of this file, hopefully tricking GitHub
into recognising this as a Go repo instead of Makefile.

A gopher, ASCII art style - borrowed from
https://gist.github.com/belbomemo/b5e7dad10fa567a5fe8a

          ,_---~~~~~----._
   _,,_,*^____      _____``*g*\"*,
  / __/ /'     ^.  /      \ ^@q   f
 [  @f | @))    |  | @))   l  0 _/
  \`/   \~____ / __ \_____/    \
   |           _l__l_           I
   }          [______]           I
   ]            | | |            |
   ]             ~ ~             |
   |                            |
    |                           |

*/
